package samlx

import (
	"testing"
	"time"

	"aegis/internal/clock"
)

func TestAssertionReplayStore(t *testing.T) {
	now := time.Unix(20000, 0)
	c := clock.NewManual(now)
	s := &SP{clock: c, used: make(map[string]time.Time)}
	if !s.reserve("fresh", now.Add(time.Minute)) || s.reserve("fresh", now.Add(time.Minute)) {
		t.Fatal("assertion replay accepted")
	}
	c.Advance(time.Minute)
	if !s.reserve("fresh", c.Now().Add(time.Minute)) {
		t.Fatal("expired replay record retained")
	}
}

func TestXMLStructureGuards(t *testing.T) {
	for _, fixture := range []string{
		"<!DOCTYPE Response [<!ENTITY example 'literal'>]><Response/>",
		"<root ID=\"one\" ID=\"two\"/>",
		"<root/><second/>",
	} {
		if xmlEnvelope([]byte(fixture), nil) == nil {
			t.Fatal("invalid XML accepted")
		}
	}
	if _, err := inspect([]byte(`<Response xmlns="urn:oasis:names:tc:SAML:2.0:protocol" ID="a"><Assertion xmlns="urn:oasis:names:tc:SAML:2.0:assertion" ID="a"/></Response>`)); err == nil {
		t.Fatal("duplicate XML ID accepted")
	}
}
