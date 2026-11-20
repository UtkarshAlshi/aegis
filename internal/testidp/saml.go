package testidp

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"html/template"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"aegis/internal/clock"
	"aegis/internal/pki"
	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlidp"
)

type SAMLMode int32

const (
	SAMLNormal SAMLMode = iota
	SAMLUnsignedAssertion
	SAMLTampered
	SAMLAmbiguous
	SAMLExpired
	SAMLWrongAudience
	SAMLWrongRecipient
	SAMLWrongInResponseTo
	SAMLWrongIssuer
	SAMLWrongDestination
	SAMLMalformed
	SAMLDirective
)

type SAML struct {
	Server *httptest.Server
	impl   *samlidp.Server
	clock  clock.Clock
	mode   atomic.Int32
}

var samlLogin = template.Must(template.New("login").Parse(`<!doctype html><html lang="en"><meta charset="utf-8"><title>Demo SAML</title><h1>Demo SAML</h1><p><a href="{{.}}">Continue as bob (engineering)</a></p></html>`))
var samlForm = template.Must(template.New("post").Parse(`<!doctype html><html lang="en"><meta charset="utf-8"><title>Continue</title><form method="post" action="{{.URL}}"><input type="hidden" name="SAMLResponse" value="{{.SAMLResponse}}"><input type="hidden" name="RelayState" value="{{.RelayState}}"><button>Return to Aegis</button></form></html>`))

func NewSAML(c clock.Clock, signing pki.Pair, transport *tls.Config) (*SAML, error) {
	pair, err := signing.TLS()
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, err
	}
	signer, ok := pair.PrivateKey.(crypto.Signer)
	if !ok {
		return nil, errors.New("invalid mock SAML signing key")
	}
	p := &SAML{clock: c}
	p.Server = httptest.NewUnstartedServer(http.HandlerFunc(p.serve))
	p.Server.TLS = transport
	origin := url.URL{Scheme: "https", Host: p.Server.Listener.Addr().String()}
	p.impl, err = samlidp.New(samlidp.Options{URL: origin, Signer: signer, Certificate: cert, Store: &samlidp.MemoryStore{}, Logger: log.New(io.Discard, "", 0)})
	if err != nil {
		p.Server.Close()
		return nil, err
	}
	p.impl.IDP.SessionProvider = p
	p.impl.IDP.AssertionMaker = p
	p.impl.IDP.ResponseWriter = p
	p.Server.StartTLS()
	return p, nil
}

func (p *SAML) serve(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	if r.Method != http.MethodGet || (r.URL.Path != "/sso" && r.URL.Path != "/metadata") {
		http.NotFound(w, r)
		return
	}
	p.impl.ServeHTTP(w, r)
}

func (p *SAML) RegisterSP(raw []byte) bool {
	r := httptest.NewRequest("PUT", "/services/aegis", strings.NewReader(string(raw)))
	w := httptest.NewRecorder()
	p.impl.ServeHTTP(w, r)
	return w.Code >= 200 && w.Code < 300
}

func (p *SAML) EntityID() string          { return p.impl.IDP.MetadataURL.String() }
func (p *SAML) Metadata() ([]byte, error) { return xml.Marshal(p.impl.IDP.Metadata()) }
func (p *SAML) SetMode(mode SAMLMode)     { p.mode.Store(int32(mode)) }
func (p *SAML) getMode() SAMLMode         { return SAMLMode(p.mode.Load()) }

func (p *SAML) GetSession(w http.ResponseWriter, r *http.Request, _ *saml.IdpAuthnRequest) *saml.Session {
	if r.URL.Query().Get("demo") != "1" {
		u := *r.URL
		q := u.Query()
		q.Set("demo", "1")
		u.RawQuery = q.Encode()
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_ = samlLogin.Execute(w, u.String())
		return nil
	}
	now := p.clock.Now()
	return &saml.Session{ID: "bob", Index: "bob-demo", NameID: "bob", NameIDFormat: string(saml.TransientNameIDFormat), CreateTime: now, ExpireTime: now.Add(time.Hour),
		CustomAttributes: []saml.Attribute{{Name: "groups", Values: []saml.AttributeValue{{Type: "xs:string", Value: "engineering"}}}}}
}

func (p *SAML) MakeAssertion(req *saml.IdpAuthnRequest, s *saml.Session) error {
	if err := (saml.DefaultAssertionMaker{}).MakeAssertion(req, s); err != nil {
		return err
	}
	a := req.Assertion
	switch p.getMode() {
	case SAMLExpired:
		a.Conditions.NotBefore = p.clock.Now().Add(-3 * time.Minute)
		a.Conditions.NotOnOrAfter = p.clock.Now().Add(-90 * time.Second)
	case SAMLWrongAudience:
		a.Conditions.AudienceRestrictions[0].Audience.Value = "https://other.example"
	case SAMLWrongRecipient:
		a.Subject.SubjectConfirmations[0].SubjectConfirmationData.Recipient = "https://other.example"
	case SAMLWrongInResponseTo:
		a.Subject.SubjectConfirmations[0].SubjectConfirmationData.InResponseTo = "other"
	case SAMLWrongIssuer:
		a.Issuer.Value = "https://other.example"
	}
	return nil
}

func (p *SAML) WriteResponse(w http.ResponseWriter, req *saml.IdpAuthnRequest) error {
	mode := p.getMode()
	if err := req.MakeResponse(); err != nil {
		return err
	}
	switch mode {
	case SAMLUnsignedAssertion:
		if err := req.MakeAssertionEl(); err != nil {
			return err
		}
		for _, child := range req.AssertionEl.ChildElements() {
			if child.Tag == "Signature" {
				req.AssertionEl.RemoveChild(child)
			}
		}
		req.ResponseEl = nil
	case SAMLTampered:
		if req.AssertionEl != nil {
			req.AssertionEl.CreateAttr("IssueInstant", p.clock.Now().Add(-time.Second).UTC().Format(time.RFC3339Nano))
		}
	case SAMLAmbiguous:
		if req.ResponseEl != nil && req.AssertionEl != nil {
			req.ResponseEl.AddChild(req.AssertionEl.Copy())
		}
	case SAMLWrongDestination:
		if req.ResponseEl != nil {
			req.ResponseEl.CreateAttr("Destination", "https://other.example")
		}
	}
	form, err := req.PostBinding()
	if err != nil {
		return err
	}
	switch mode {
	case SAMLMalformed:
		form.SAMLResponse = base64.StdEncoding.EncodeToString([]byte("<Response"))
	case SAMLDirective:
		form.SAMLResponse = base64.StdEncoding.EncodeToString([]byte("<!DOCTYPE Response><Response/>"))
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	return samlForm.Execute(w, form)
}
