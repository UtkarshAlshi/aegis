package authz

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path"
	"slices"
	"strings"
	"sync/atomic"

	"aegis/internal/session"
	"gopkg.in/yaml.v3"
)

const maxPolicy = 256 << 10

type Rule struct {
	Prefix   string   `yaml:"path_prefix"`
	Methods  []string `yaml:"methods"`
	Groups   []string `yaml:"groups"`
	Roles    []string `yaml:"roles"`
	Machines []string `yaml:"machines"`
	Deny     bool     `yaml:"deny"`
}

type policy struct {
	Rules []Rule `yaml:"rules"`
}

type Engine struct{ active atomic.Pointer[policy] }

func (e *Engine) Reload(file string) error {
	f, err := os.Open(file)
	if err != nil {
		return err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, maxPolicy+1))
	if err != nil {
		return err
	}
	return e.Load(raw)
}

func (e *Engine) Load(raw []byte) error {
	if len(raw) > maxPolicy {
		return errors.New("policy exceeds size limit")
	}
	var p policy
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(&p); err != nil {
		return err
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		return errors.New("expected one policy document")
	}
	for _, r := range p.Rules {
		if !ValidPath(r.Prefix) || len(r.Methods) == 0 || (!r.Deny && len(r.Groups)+len(r.Roles)+len(r.Machines) == 0) {
			return errors.New("invalid policy rule")
		}
		for _, m := range r.Methods {
			if m == "" || strings.ContainsFunc(m, func(c rune) bool { return c < 'A' || c > 'Z' }) {
				return errors.New("invalid method")
			}
		}
		for _, values := range [][]string{r.Groups, r.Roles, r.Machines} {
			for _, v := range values {
				if v == "" || strings.TrimSpace(v) != v {
					return errors.New("invalid identity matcher")
				}
			}
		}
	}
	e.active.Store(&p)
	return nil
}

func ValidPath(p string) bool {
	return strings.HasPrefix(p, "/") && !strings.ContainsAny(p, "\\%\x00\r\n") && path.Clean(p) == p
}

func (e *Engine) Allow(path, method string, id session.Identity) bool {
	p := e.active.Load()
	if p == nil || !ValidPath(path) || id.Subject == "" {
		return false
	}
	for _, r := range p.Rules {
		if !slices.Contains(r.Methods, method) || (r.Prefix != "/" && r.Prefix != path && !strings.HasPrefix(path, r.Prefix+"/")) {
			continue
		}
		if r.Deny {
			return false
		}
		switch id.Kind {
		case "machine":
			return slices.Contains(r.Machines, id.Subject)
		case "user":
			return len(r.Groups)+len(r.Roles) > 0 && includes(id.Groups, r.Groups) && includes(id.Roles, r.Roles)
		default:
			return false
		}
	}
	return false
}

func includes(have, need []string) bool {
	for _, v := range need {
		if !slices.Contains(have, v) {
			return false
		}
	}
	return true
}
