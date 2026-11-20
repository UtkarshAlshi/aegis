package authz

import (
	"os"
	"path/filepath"
	"testing"

	"aegis/internal/session"
)

func TestPolicyMatrixAndBadReload(t *testing.T) {
	file := filepath.Join(t.TempDir(), "policy.yaml")
	valid := []byte(`rules:
  - path_prefix: /data/private
    methods: [GET]
    deny: true
  - path_prefix: /data
    methods: [GET]
    groups: [engineering]
    roles: [reader]
    machines: [spiffe://aegis/service/robot]
`)
	if err := os.WriteFile(file, valid, 0600); err != nil {
		t.Fatal(err)
	}
	e := &Engine{}
	if err := e.Reload(file); err != nil {
		t.Fatal(err)
	}
	user := session.Identity{Kind: "user", Subject: "alice", Groups: []string{"engineering"}, Roles: []string{"reader"}}
	machine := session.Identity{Kind: "machine", Subject: "spiffe://aegis/service/robot"}
	for _, tc := range []struct {
		path, method string
		id           session.Identity
		want         bool
	}{
		{"/data", "GET", user, true}, {"/data/sub", "GET", machine, true},
		{"/data/private", "GET", user, false}, {"/database", "GET", user, false}, {"/data/../data", "GET", user, false},
		{"/data", "POST", machine, false}, {"/data", "GET", session.Identity{}, false},
		{"/data", "GET", session.Identity{Kind: "user", Subject: "alice", Groups: user.Groups}, false},
		{"/data", "GET", session.Identity{Kind: "machine", Subject: "other"}, false},
	} {
		if e.Allow(tc.path, tc.method, tc.id) != tc.want {
			t.Errorf("%s %s (%s): want %v", tc.method, tc.path, tc.id.Subject, tc.want)
		}
	}
	if err := os.WriteFile(file, []byte("rules: [{unknown: true}]"), 0600); err != nil {
		t.Fatal(err)
	}
	if e.Reload(file) == nil || !e.Allow("/data", "GET", user) {
		t.Fatal("bad reload changed active policy")
	}
}
