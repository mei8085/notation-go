// Copyright The Notary Project Authors.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package pkix

import (
	"crypto/x509"
	"errors"
	"fmt"
	"strings"

	ldapv3 "github.com/go-ldap/ldap/v3"
	"github.com/notaryproject/notation-go/internal/slices"
)

// attributeTypeOIDNames maps attribute type OIDs to their short names as
// defined in RFC 4514 section 3 and RFC 5280. Unknown OIDs are kept in
// their dotted-decimal representation, following RFC 4514.
var attributeTypeOIDNames = map[string]string{
	"2.5.4.3":                    "CN",
	"2.5.4.4":                    "SN",
	"2.5.4.5":                    "SERIALNUMBER",
	"2.5.4.6":                    "C",
	"2.5.4.7":                    "L",
	"2.5.4.8":                    "ST",
	"2.5.4.9":                    "STREET",
	"2.5.4.10":                   "O",
	"2.5.4.11":                   "OU",
	"2.5.4.12":                   "T",
	"2.5.4.42":                   "GN",
	"0.9.2342.19200300.100.1.1":  "UID",
	"0.9.2342.19200300.100.1.25": "DC",
	"1.2.840.113549.1.9.1":       "E",
}

// ParseDistinguishedName parses a DN name and validates Notary Project rules
func ParseDistinguishedName(name string) (map[string]string, error) {
	if strings.Contains(name, "=#") {
		return nil, fmt.Errorf("unsupported distinguished name (DN) %q: notation does not support x509.subject identities containing \"=#\"", name)
	}

	attrKeyValue := make(map[string]string)
	dn, err := ldapv3.ParseDN(name)
	if err != nil {
		return nil, fmt.Errorf("parsing distinguished name (DN) %q failed with err: %v. A valid DN must contain 'C', 'ST' or 'S', and 'O' RDN attributes at a minimum, and follow RFC 4514 standard", name, err)
	}

	for _, rdn := range dn.RDNs {
		// multi-valued RDNs are not supported (TODO: add spec reference here)
		if len(rdn.Attributes) > 1 {
			return nil, fmt.Errorf("distinguished name (DN) %q has multi-valued RDN attributes, remove multi-valued RDN attributes as they are not supported", name)
		}
		for _, attribute := range rdn.Attributes {
			// stateOrProvince name 'S' is an alias for 'ST'
			if attribute.Type == "S" {
				attribute.Type = "ST"
			}
			if attrKeyValue[attribute.Type] == "" {
				attrKeyValue[attribute.Type] = attribute.Value
			} else {
				return nil, fmt.Errorf("distinguished name (DN) %q has duplicate RDN attribute for %q, DN can only have unique RDN attributes", name, attribute.Type)
			}
		}
	}

	// Verify mandatory fields are present
	mandatoryFields := []string{"C", "ST", "O"}
	for _, field := range mandatoryFields {
		if attrKeyValue[field] == "" {
			return nil, fmt.Errorf("distinguished name (DN) %q has no mandatory RDN attribute for %q, it must contain 'C', 'ST' or 'S', and 'O' RDN attributes at a minimum", name, field)
		}
	}

	// No errors
	return attrKeyValue, nil
}

// IsSubsetDN returns true if dn1 is a subset of dn2 i.e. every key/value pair
// of dn1 has a matching key/value pair in dn2, otherwise returns false.
// Attribute values are compared following X.501 caseIgnoreMatch semantics,
// i.e. case-insensitively, as both DNs hold DirectoryString values.
func IsSubsetDN(dn1 map[string]string, dn2 map[string]string) bool {
	for key := range dn1 {
		if !strings.EqualFold(dn1[key], dn2[key]) {
			return false
		}
	}
	return true
}

// ParseCertDistinguishedName parses the subject of cert into a normalized
// multi-valued attribute map following X.501 / RFC 5280 certificate
// semantics. Unlike ParseDistinguishedName, which validates the Notary
// Project rules for trusted identity strings, this function accepts
// certificate subjects containing multi-valued RDNs and repeated attributes,
// which are legitimate in X.509 certificates. Each attribute type maps to
// the set of distinct values present in the subject, so matching does not
// depend on RDN order, SET order within a multi-valued RDN, or string
// escaping representations.
//
// A certificate whose subject is empty, or that carries attribute values
// that cannot be processed (e.g. non-string ASN.1 types), is explicitly
// rejected with an error.
func ParseCertDistinguishedName(cert *x509.Certificate) (map[string][]string, error) {
	if cert == nil {
		return nil, errors.New("cannot parse distinguished name (DN) from a nil certificate")
	}
	if len(cert.Subject.Names) == 0 {
		return nil, errors.New("certificate subject is empty, it must contain at least one RDN attribute")
	}

	attrKeyValues := make(map[string][]string)
	for _, atv := range cert.Subject.Names {
		attrType := atv.Type.String()
		if shortName, ok := attributeTypeOIDNames[attrType]; ok {
			attrType = shortName
		}
		value, ok := atv.Value.(string)
		if !ok {
			return nil, fmt.Errorf("certificate subject attribute %q has a non-string value of ASN.1 type %T, which cannot be processed", attrType, atv.Value)
		}
		if !slices.Contains(attrKeyValues[attrType], value) {
			attrKeyValues[attrType] = append(attrKeyValues[attrType], value)
		}
	}
	return attrKeyValues, nil
}

// IsSubsetOfCertDN returns true if every attribute type/value pair of the
// trusted identity dn has a matching attribute value in certDN, a
// certificate subject parsed by ParseCertDistinguishedName. Attribute values
// are compared following X.501 caseIgnoreMatch semantics, i.e.
// case-insensitively. A repeated certificate attribute matches if any of its
// values equals the trusted identity value.
func IsSubsetOfCertDN(dn map[string]string, certDN map[string][]string) bool {
	for key, value := range dn {
		certValues, ok := certDN[key]
		if !ok {
			return false
		}
		matched := false
		for _, certValue := range certValues {
			if strings.EqualFold(certValue, value) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	return true
}
