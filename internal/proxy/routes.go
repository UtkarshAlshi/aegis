package proxy

import (
	"encoding/json"
	"html/template"
	"net/http"

	"aegis/internal/oidc"
)

var home = template.Must(template.New("home").Parse(`<!doctype html><html lang="en"><meta charset="utf-8"><title>Aegis</title><h1>Aegis</h1>{{if .Subject}}<p>Signed in as {{.Subject}}</p><p><a href="/protected">Open protected route</a></p><form action="/auth/logout" method="post"><input type="hidden" name="csrf" value="{{.CSRF}}"><button>Sign out</button></form>{{else}}{{if .OIDC}}<p><a href="/auth/oidc/login">Sign in with OIDC</a></p>{{end}}{{if .SAML}}<p><a href="/auth/saml/login">Sign in with SAML</a></p>{{end}}{{end}}</html>`))

func (g *Gateway) BrowserRoutes(p *oidc.RP, saml bool) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/jwks.json", g.JWKS)
	if p != nil {
		mux.HandleFunc("GET /auth/oidc/login", p.Login)
		mux.HandleFunc("GET /auth/oidc/callback", p.Callback)
	}
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		id, csrf, _ := g.Sessions.Authenticate(r)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; form-action 'self'; frame-ancestors 'none'")
		_ = home.Execute(w, struct {
			Subject, CSRF string
			OIDC, SAML    bool
		}{id.Subject, csrf, p != nil, saml})
	})
	mux.HandleFunc("GET /auth/session", func(w http.ResponseWriter, r *http.Request) {
		id, csrf, err := g.Sessions.Authenticate(r)
		if err != nil {
			http.Error(w, "authentication required", 401)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"subject": id.Subject, "csrf_token": csrf})
	})
	mux.HandleFunc("POST /auth/logout", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-CSRF-Token") == "" && r.PostFormValue("csrf") != "" {
			r.Header.Set("X-CSRF-Token", r.PostFormValue("csrf"))
		}
		if _, _, err := g.Sessions.Authenticate(r); err != nil {
			g.Audit.Event("session", "logout_rejected", false)
			http.Error(w, "forbidden", 403)
			return
		}
		g.Sessions.Logout(w, r)
		g.Audit.Event("session", "logout", true)
		http.Redirect(w, r, "/", http.StatusSeeOther)
	})
	mux.Handle("/auth/", http.NotFoundHandler())
	mux.Handle("/", g)
	return mux
}
