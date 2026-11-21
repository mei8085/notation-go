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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"reflect"
	"testing"
	"time"
)

func TestParseDistinguishedName(t *testing.T) {
	// Test cases
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{
			name:    "valid DN",
			input:   "C=US,ST=California,O=Notary Project",
			wantErr: false,
		},
		{
			name:    "valid DN with State alias",
			input:   "C=US,S=California,O=Notary Project",
			wantErr: false,
		},
		{
			name:    "invalid DN",
			input:   "C=US,ST=California",
			wantErr: true,
		},
		{
			name:    "invalid DN without State",
			input:   "C=US,O=Notary Project",
			wantErr: true,
		},
		{
			name:    "invalid DN without State",
			input:   "invalid",
			wantErr: true,
		},
		{
			name:    "duplicate RDN attribute",
			input:   "C=US,ST=California,O=Notary Project,S=California",
			wantErr: true,
		},
		{
			name:    "unsupported DN =#",
			input:   "C=US,ST=California,O=Notary Project=#",
			wantErr: true,
		},
		{
			name:    "multi-valued RDN attributes",
			input:   "OU=Sales+CN=J.  Smith,DC=example,DC=net",
			wantErr: true,
		},
	}

	// Run tests
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseDistinguishedName(tt.input)
			if tt.wantErr != (err != nil) {
				t.Errorf("ParseDistinguishedName() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestParseCertDistinguishedName(t *testing.T) {
	oidC := asn1.ObjectIdentifier{2, 5, 4, 6}
	oidST := asn1.ObjectIdentifier{2, 5, 4, 8}
	oidO := asn1.ObjectIdentifier{2, 5, 4, 10}
	oidOU := asn1.ObjectIdentifier{2, 5, 4, 11}
	oidCN := asn1.ObjectIdentifier{2, 5, 4, 3}
	oidUnknown := asn1.ObjectIdentifier{1, 2, 3, 4}

	certFromRDNSequence := func(rdnSeq pkix.RDNSequence) *x509.Certificate {
		var name pkix.Name
		name.FillFromRDNSequence(&rdnSeq)
		return &x509.Certificate{Subject: name}
	}

	t.Run("nil certificate", func(t *testing.T) {
		if _, err := ParseCertDistinguishedName(nil); err == nil {
			t.Fatal("expected error for nil certificate")
		}
	})

	t.Run("empty subject is rejected", func(t *testing.T) {
		if _, err := ParseCertDistinguishedName(&x509.Certificate{}); err == nil {
			t.Fatal("expected error for empty certificate subject")
		}
	})

	t.Run("non-string attribute value is rejected", func(t *testing.T) {
		cert := &x509.Certificate{Subject: pkix.Name{
			Names: []pkix.AttributeTypeAndValue{
				{Type: oidC, Value: "US"},
				{Type: oidCN, Value: asn1.RawValue{Tag: 4, Bytes: []byte{1, 2, 3}}},
			},
		}}
		if _, err := ParseCertDistinguishedName(cert); err == nil {
			t.Fatal("expected error for non-string attribute value")
		}
	})

	t.Run("multi-valued RDN and repeated attributes", func(t *testing.T) {
		cert := certFromRDNSequence(pkix.RDNSequence{
			{{Type: oidC, Value: "US"}},
			{{Type: oidST, Value: "WA"}},
			{{Type: oidO, Value: "SomeOrg"}},
			// multi-valued RDN
			{{Type: oidOU, Value: "Sales"}, {Type: oidCN, Value: "J. Smith"}},
			// repeated attribute
			{{Type: oidOU, Value: "Engineering"}},
			// duplicate value is collapsed
			{{Type: oidOU, Value: "Engineering"}},
			// unknown OID keeps its dotted-decimal form
			{{Type: oidUnknown, Value: "custom"}},
		})
		got, err := ParseCertDistinguishedName(cert)
		if err != nil {
			t.Fatalf("ParseCertDistinguishedName() error = %v", err)
		}
		want := map[string][]string{
			"C":       {"US"},
			"ST":      {"WA"},
			"O":       {"SomeOrg"},
			"OU":      {"Sales", "Engineering"},
			"CN":      {"J. Smith"},
			"1.2.3.4": {"custom"},
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("ParseCertDistinguishedName() = %v, want %v", got, want)
		}
	})

	t.Run("certificate parsed from DER with repeated attributes", func(t *testing.T) {
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		template := &x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject: pkix.Name{
				Country:      []string{"US"},
				Province:     []string{"WA"},
				Organization: []string{"SomeOrg"},
				ExtraNames: []pkix.AttributeTypeAndValue{
					{Type: oidOU, Value: "Sales"},
					{Type: oidOU, Value: "Engineering"},
				},
			},
			NotBefore:             time.Now(),
			NotAfter:              time.Now().Add(time.Hour),
			BasicConstraintsValid: true,
		}
		der, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
		if err != nil {
			t.Fatal(err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		got, err := ParseCertDistinguishedName(cert)
		if err != nil {
			t.Fatalf("ParseCertDistinguishedName() error = %v", err)
		}
		want := map[string][]string{
			"C":  {"US"},
			"ST": {"WA"},
			"O":  {"SomeOrg"},
			"OU": {"Sales", "Engineering"},
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("ParseCertDistinguishedName() = %v, want %v", got, want)
		}
	})
}

func TestIsSubsetOfCertDN(t *testing.T) {
	certDN := map[string][]string{
		"C":  {"US"},
		"ST": {"WA"},
		"O":  {"SomeOrg"},
		"OU": {"Sales", "Engineering"},
	}
	tests := []struct {
		name string
		dn   map[string]string
		want bool
	}{
		{
			name: "subset",
			dn:   map[string]string{"C": "US", "ST": "WA", "O": "SomeOrg"},
			want: true,
		},
		{
			name: "case is normalized",
			dn:   map[string]string{"C": "us", "ST": "wa", "O": "someorg"},
			want: true,
		},
		{
			name: "matches one of the repeated attribute values",
			dn:   map[string]string{"C": "US", "ST": "WA", "O": "SomeOrg", "OU": "Engineering"},
			want: true,
		},
		{
			name: "conflicting attribute value",
			dn:   map[string]string{"C": "US", "ST": "WA", "O": "SomeOrg", "OU": "Marketing"},
			want: false,
		},
		{
			name: "missing attribute",
			dn:   map[string]string{"C": "US", "ST": "WA", "O": "SomeOrg", "CN": "Notary"},
			want: false,
		},
		{
			name: "different value",
			dn:   map[string]string{"C": "US", "ST": "WA", "O": "OtherOrg"},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsSubsetOfCertDN(tt.dn, certDN); got != tt.want {
				t.Errorf("IsSubsetOfCertDN() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsSubsetDN(t *testing.T) {
	// Test cases
	tests := []struct {
		name string
		dn1  map[string]string
		dn2  map[string]string
		want bool
	}{
		{
			name: "subset DN",
			dn1: map[string]string{
				"C":  "US",
				"ST": "California",
				"O":  "Notary Project",
			},
			dn2: map[string]string{
				"C":  "US",
				"ST": "California",
				"O":  "Notary Project",
				"L":  "Los Angeles",
			},
			want: true,
		},
		{
			name: "not subset DN",
			dn1: map[string]string{
				"C":  "US",
				"ST": "California",
				"O":  "Notary Project",
			},
			dn2: map[string]string{
				"C":  "US",
				"ST": "California",
				"O":  "Notary Project 2",
				"L":  "Los Angeles",
				"CN": "Notary",
			},
			want: false,
		},
		{
			name: "not subset DN 2",
			dn1: map[string]string{
				"C":  "US",
				"ST": "California",
				"O":  "Notary Project",
				"CN": "Notary",
			},
			dn2: map[string]string{
				"C":  "US",
				"ST": "California",
				"O":  "Notary Project",
				"L":  "Los Angeles",
			},
			want: false,
		},
	}

	// Run tests
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsSubsetDN(tt.dn1, tt.dn2); got != tt.want {
				t.Errorf("IsSubsetDN() = %v, want %v", got, tt.want)
			}
		})
	}
}
