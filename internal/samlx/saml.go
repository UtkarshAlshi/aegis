package samlx

import (
	"bytes"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"io"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"aegis/internal/audit"
	"aegis/internal/clock"
	"aegis/internal/oidc"
	"aegis/internal/session"
	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"
)

const pendingCookie = "__Host-aegis-saml"
const ttl = 5 * time.Minute
const skew = time.Minute
const maxXML = 256 << 10
const assertionNS = "urn:oasis:names:tc:SAML:2.0:assertion"
const protocolNS = "urn:oasis:names:tc:SAML:2.0:protocol"
const signatureNS = "http://www.w3.org/2000/09/xmldsig#"
const bearer = "urn:oasis:names:tc:SAML:2.0:cm:bearer"

type login struct{ requestID, oldSession string }

type SP struct {
	clock    clock.Clock
	sp       saml.ServiceProvider
	endpoint string
	pending  *session.Pending[login]
	sessions *session.Store
	audit    *audit.Log
	mu       sync.Mutex
	used     map[string]time.Time
}

func New(c clock.Clock, origin, entityID string, metadata []byte, s *session.Store, a *audit.Log) (*SP, error) {
	if c == nil || s == nil || entityID == "" || len(metadata) == 0 || len(metadata) > maxXML || xmlEnvelope(metadata, nil) != nil {
		return nil, errors.New("invalid SAML configuration")
	}
	base, err := oidc.SecureURL(origin)
	if err != nil || base.Path != "" || base.RawQuery != "" || base.ForceQuery {
		return nil, errors.New("invalid SP origin")
	}
	idp, err := samlsp.ParseMetadataByEntityID(metadata, entityID)
	if err != nil || idp.EntityID != entityID || len(idp.IDPSSODescriptors) != 1 || (!idp.ValidUntil.IsZero() && !c.Now().Before(idp.ValidUntil)) {
		return nil, errors.New("IdP metadata rejected")
	}
	var signingKeys int
	var redirect string
	for _, d := range idp.IDPSSODescriptors {
		for _, key := range d.KeyDescriptors {
			if key.Use == "" || key.Use == "signing" {
				signingKeys += len(key.KeyInfo.X509Data.X509Certificates)
			}
		}
		for _, binding := range d.SingleSignOnServices {
			if binding.Binding == saml.HTTPRedirectBinding {
				if redirect != "" {
					return nil, errors.New("ambiguous IdP redirect binding")
				}
				redirect = binding.Location
			}
		}
	}
	if _, err = oidc.SecureURL(redirect); err != nil || signingKeys == 0 {
		return nil, errors.New("IdP signing keys and HTTPS SSO are required")
	}
	metadataURL, acsURL := *base, *base
	metadataURL.Path = "/auth/saml/metadata"
	acsURL.Path = "/auth/saml/acs"
	sp := saml.ServiceProvider{EntityID: metadataURL.String(), MetadataURL: metadataURL, AcsURL: acsURL, IDPMetadata: idp, RejectUnknownConditions: true}
	return &SP{clock: c, sp: sp, endpoint: redirect, pending: session.NewPending[login](c, ttl), sessions: s, audit: a, used: make(map[string]time.Time)}, nil
}

func (s *SP) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /auth/saml/login", s.Login)
	mux.HandleFunc("POST /auth/saml/acs", s.ACS)
	mux.HandleFunc("GET /auth/saml/metadata", s.Metadata)
}

func (s *SP) Metadata(w http.ResponseWriter, _ *http.Request) {
	raw, err := s.MetadataXML()
	if err != nil {
		http.Error(w, "metadata unavailable", 500)
		return
	}
	w.Header().Set("Content-Type", "application/samlmetadata+xml")
	_, _ = w.Write(raw)
}
func (s *SP) MetadataXML() ([]byte, error) {
	m := s.sp.Metadata()
	m.ValidUntil = s.clock.Now().Add(24 * time.Hour)
	return xml.Marshal(m)
}
func (s *SP) fail(w http.ResponseWriter, why string, status int) {
	s.audit.Event("saml", why, false)
	http.Error(w, "sign-in failed", status)
}

func (s *SP) Login(w http.ResponseWriter, r *http.Request) {
	req, err := s.sp.MakeAuthenticationRequest(s.endpoint, saml.HTTPRedirectBinding, saml.HTTPPostBinding)
	if err != nil {
		s.fail(w, "request_unavailable", 503)
		return
	}
	req.IssueInstant = s.clock.Now().UTC()
	state, err := session.Random()
	if err != nil {
		s.fail(w, "state_unavailable", 503)
		return
	}
	target, err := req.Redirect(state, &s.sp)
	if err != nil || s.pending.Add(state, login{req.ID, session.CurrentID(r)}) != nil {
		s.fail(w, "state_unavailable", 503)
		return
	}
	// The IdP posts across sites. Only the short-lived relay cookie needs SameSite=None.
	session.SetCookie(w, pendingCookie, state, ttl, http.SameSiteNoneMode)
	http.Redirect(w, r, target.String(), 303)
}

func (s *SP) ACS(w http.ResponseWriter, r *http.Request) {
	if r.URL.RawQuery != "" || r.ParseForm() != nil || len(r.PostForm["RelayState"]) != 1 || len(r.PostForm["SAMLResponse"]) != 1 {
		s.fail(w, "form_invalid", 400)
		return
	}
	flow, ok := s.pending.Take(r, pendingCookie, r.PostForm.Get("RelayState"))
	if !ok {
		s.fail(w, "relay_invalid", 400)
		return
	}
	session.SetCookie(w, pendingCookie, "", -1, http.SameSiteNoneMode)
	encoded := r.PostForm.Get("SAMLResponse")
	if len(encoded) > base64.StdEncoding.EncodedLen(maxXML) {
		s.fail(w, "response_size", 400)
		return
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil || len(raw) > maxXML {
		s.fail(w, "response_encoding", 400)
		return
	}
	id, err := s.validate(raw, flow.requestID)
	if err != nil {
		s.fail(w, "assertion_rejected", 401)
		return
	}
	if err = s.sessions.Login(w, r, id); err != nil {
		s.fail(w, "session_unavailable", 503)
		return
	}
	s.sessions.Revoke(flow.oldSession)
	s.audit.Event("saml", "login", true)
	http.Redirect(w, r, "/", 303)
}

func (s *SP) validate(raw []byte, requestID string) (session.Identity, error) {
	var id session.Identity
	envelope, err := inspect(raw)
	if err != nil {
		return id, err
	}
	if envelope.Destination != s.sp.AcsURL.String() || envelope.InResponseTo != requestID ||
		envelope.Issuer == nil || envelope.Issuer.Value != s.sp.IDPMetadata.EntityID {
		return id, errors.New("response context mismatch")
	}
	a, err := s.sp.ParseXMLResponse(raw, []string{requestID}, s.sp.AcsURL)
	if err != nil || a == nil {
		return id, errors.New("SAML signature or protocol rejected")
	}
	now := s.clock.Now()
	if a.ID != envelope.Assertion.ID || a.Issuer.Value != s.sp.IDPMetadata.EntityID ||
		a.Subject == nil || a.Subject.NameID == nil || strings.TrimSpace(a.Subject.NameID.Value) == "" ||
		a.Conditions == nil || a.IssueInstant.IsZero() || a.IssueInstant.After(now.Add(skew)) ||
		!now.Before(a.IssueInstant.Add(ttl+skew)) || !timeWindow(now, a.Conditions.NotBefore, a.Conditions.NotOnOrAfter) ||
		len(a.Subject.SubjectConfirmations) != 1 ||
		len(a.Conditions.AudienceRestrictions) == 0 {
		return id, errors.New("signed assertion claims rejected")
	}
	for _, restriction := range a.Conditions.AudienceRestrictions {
		if !slices.ContainsFunc(restriction.AllAudiences(), func(entry saml.Audience) bool { return entry.Value == s.sp.EntityID }) {
			return id, errors.New("assertion audience mismatch")
		}
	}
	confirm := a.Subject.SubjectConfirmations[0]
	d := confirm.SubjectConfirmationData
	if confirm.Method != bearer || d == nil || d.Recipient != s.sp.AcsURL.String() || d.InResponseTo != requestID ||
		!d.NotBefore.IsZero() || d.NotOnOrAfter.IsZero() || !now.Before(d.NotOnOrAfter.Add(skew)) {
		return id, errors.New("bearer confirmation rejected")
	}
	if !s.reserve(a.ID, minTime(a.Conditions.NotOnOrAfter, d.NotOnOrAfter, a.IssueInstant.Add(ttl)).Add(skew)) {
		return id, errors.New("assertion replay or capacity")
	}
	id = session.Identity{Subject: a.Subject.NameID.Value, Kind: "user", Provider: "saml"}
	for _, statement := range a.AttributeStatements {
		for _, attr := range statement.Attributes {
			for _, v := range attr.Values {
				switch attr.Name {
				case "groups":
					id.Groups = append(id.Groups, v.Value)
				case "roles":
					id.Roles = append(id.Roles, v.Value)
				}
			}
		}
	}
	return id, nil
}

func timeWindow(now, start, end time.Time) bool {
	return !start.IsZero() && !end.IsZero() && start.Before(end) &&
		!start.After(now.Add(skew)) && now.Before(end.Add(skew))
}

func minTime(first time.Time, others ...time.Time) time.Time {
	for _, t := range others {
		if t.Before(first) {
			first = t
		}
	}
	return first
}

func (s *SP) reserve(id string, expiry time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, v := range s.used {
		if !s.clock.Now().Before(v) {
			delete(s.used, k)
		}
	}
	if _, found := s.used[id]; found || len(s.used) >= 10000 {
		return false
	}
	s.used[id] = expiry
	return true
}

func name(ns, local string) xml.Name { return xml.Name{Space: ns, Local: local} }

// xmlEnvelope rejects entities, encoding switches, excessive nesting and duplicate attributes.
func xmlEnvelope(raw []byte, visit func(xml.StartElement, []xml.Name) error) error {
	if len(raw) > maxXML {
		return errors.New("XML exceeds limit")
	}
	dec := xml.NewDecoder(bytes.NewReader(raw))
	var stack []xml.Name
	count := 0
	for {
		token, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return errors.New("malformed XML")
		}
		switch t := token.(type) {
		case xml.Directive:
			return errors.New("XML directive prohibited")
		case xml.ProcInst:
			if t.Target != "xml" || count != 0 {
				return errors.New("processing instruction prohibited")
			}
		case xml.StartElement:
			if len(stack) == 0 {
				count++
			}
			if len(stack) >= 32 {
				return errors.New("XML depth exceeded")
			}
			seen := make(map[xml.Name]bool)
			for _, attr := range t.Attr {
				if seen[attr.Name] {
					return errors.New("duplicate XML attribute")
				}
				seen[attr.Name] = true
			}
			if visit != nil {
				if err := visit(t, stack); err != nil {
					return err
				}
			}
			stack = append(stack, t.Name)
		case xml.EndElement:
			stack = stack[:len(stack)-1]
		case xml.CharData:
			if len(stack) == 0 && len(bytes.TrimSpace(t)) != 0 {
				return errors.New("unexpected XML text")
			}
		}
	}
	if count != 1 || len(stack) != 0 {
		return errors.New("expected one XML root")
	}
	return nil
}
