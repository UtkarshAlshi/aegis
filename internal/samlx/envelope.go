package samlx

import (
	"encoding/xml"
	"errors"
	"strings"

	"github.com/crewjam/saml"
)

// inspect enforces one plaintext assertion and one signature referencing it.
func inspect(raw []byte) (saml.Response, error) {
	var response saml.Response
	var assertions, signatures, references, nameIDs int
	var assertionID string
	ids := make(map[string]bool)
	root := name(protocolNS, "Response")
	assertion := name(assertionNS, "Assertion")
	signature := name(signatureNS, "Signature")
	bad := errors.New("ambiguous SAML envelope")
	err := xmlEnvelope(raw, func(t xml.StartElement, parents []xml.Name) error {
		depth := len(parents)
		if depth == 0 && t.Name != root {
			return bad
		}
		for _, attr := range t.Attr {
			switch attr.Name.Local {
			case "ID":
				if attr.Name.Space != "" || strings.TrimSpace(attr.Value) == "" || ids[attr.Value] {
					return bad
				}
				ids[attr.Value] = true
				if t.Name == assertion {
					assertionID = attr.Value
				}
			case "Destination", "InResponseTo", "Recipient", "NotBefore", "NotOnOrAfter", "URI":
				if attr.Name.Space != "" {
					return bad
				}
			}
		}
		switch t.Name.Local {
		case "Assertion":
			if t.Name != assertion || depth != 1 || parents[0] != root {
				return bad
			}
			assertions++
		case "EncryptedAssertion", "EncryptedID", "EncryptedAttribute":
			return bad
		case "NameID":
			if t.Name != name(assertionNS, "NameID") || depth != 3 || parents[1] != assertion || parents[2] != name(assertionNS, "Subject") {
				return bad
			}
			nameIDs++
		case "Signature":
			if t.Name != signature || depth < 1 || depth > 2 {
				return bad
			}
			if depth == 2 {
				if parents[1] != assertion {
					return bad
				}
				signatures++
			}
		case "Reference":
			if depth == 4 && parents[1] == assertion && parents[2] == signature && parents[3] == name(signatureNS, "SignedInfo") {
				if t.Name != name(signatureNS, "Reference") {
					return bad
				}
				references++
				for _, attr := range t.Attr {
					if attr.Name == (xml.Name{Local: "URI"}) && attr.Value == "#"+assertionID {
						return nil
					}
				}
				return bad
			}
		}
		return nil
	})
	if err != nil {
		return response, err
	}
	if assertions != 1 || signatures != 1 || references != 1 || nameIDs != 1 || assertionID == "" {
		return response, bad
	}
	if xml.Unmarshal(raw, &response) != nil || response.Assertion == nil || response.Assertion.ID != assertionID {
		return response, bad
	}
	return response, nil
}
