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

package verifier

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/notaryproject/notation-core-go/signature"
	"github.com/notaryproject/notation-core-go/signature/jws"
	"github.com/notaryproject/notation-core-go/testhelper"
	"github.com/notaryproject/notation-go"
	"github.com/notaryproject/notation-go/internal/envelope"
	"github.com/notaryproject/notation-go/internal/mock"
	"github.com/notaryproject/notation-go/plugin/proto"
	"github.com/notaryproject/notation-go/verifier/trustpolicy"
	"github.com/notaryproject/notation-go/verifier/truststore"
)

func TestGetUnprocessedCriticalExtendedAttributes(t *testing.T) {
	tests := []struct {
		name     string
		attrs    []signature.Attribute
		wantKeys []string
		wantErr  bool
	}{
		{
			name:  "no extended attributes",
			attrs: nil,
		},
		{
			name: "non-critical unknown attribute is informational",
			attrs: []signature.Attribute{
				{Key: "unknownKey", Critical: false, Value: "unknownValue"},
			},
		},
		{
			name: "critical unknown attribute must be processed",
			attrs: []signature.Attribute{
				{Key: "unknownKey", Critical: true, Value: "unknownValue"},
			},
			wantKeys: []string{"unknownKey"},
		},
		{
			name: "critical plugin attribute is handled by notation",
			attrs: []signature.Attribute{
				{Key: HeaderVerificationPlugin, Critical: true, Value: "plugin-name"},
			},
		},
		{
			name: "critical plugin min version is handled when plugin attribute present",
			attrs: []signature.Attribute{
				{Key: HeaderVerificationPlugin, Critical: true, Value: "plugin-name"},
				{Key: HeaderVerificationPluginMinVersion, Critical: true, Value: "1.0.0"},
			},
		},
		{
			name: "critical plugin min version is NOT handled when plugin attribute absent",
			attrs: []signature.Attribute{
				{Key: HeaderVerificationPluginMinVersion, Critical: true, Value: "1.0.0"},
			},
			wantKeys: []string{HeaderVerificationPluginMinVersion},
		},
		{
			name: "non-critical plugin attributes are not processed and not required",
			attrs: []signature.Attribute{
				{Key: HeaderVerificationPlugin, Critical: false, Value: "plugin-name"},
			},
		},
		{
			name: "multiple critical attributes are all returned",
			attrs: []signature.Attribute{
				{Key: "keyA", Critical: true, Value: "a"},
				{Key: "keyB", Critical: true, Value: "b"},
			},
			wantKeys: []string{"keyA", "keyB"},
		},
		{
			name: "non-string critical key is malformed",
			attrs: []signature.Attribute{
				{Key: 42, Critical: true, Value: "numeric"},
			},
			wantErr: true,
		},
		{
			name: "non-string non-critical key is ignored",
			attrs: []signature.Attribute{
				{Key: 42, Critical: false, Value: "numeric"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			signerInfo := &signature.SignerInfo{
				SignedAttributes: signature.SignedAttributes{
					ExtendedAttributes: tt.attrs,
				},
			}
			attrs, err := getUnprocessedCriticalExtendedAttributes(signerInfo)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected an error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(attrs) != len(tt.wantKeys) {
				t.Fatalf("expected %d unprocessed attributes, got %d: %v", len(tt.wantKeys), len(attrs), attrs)
			}
			for i, attr := range attrs {
				if attr.Key != tt.wantKeys[i] {
					t.Fatalf("expected key %q at index %d, got %v", tt.wantKeys[i], i, attr.Key)
				}
				if !attr.Critical {
					t.Fatalf("returned attribute %v is not critical", attr.Key)
				}
			}
		})
	}
}

func TestVerifyProcessedCriticalExtendedAttributes(t *testing.T) {
	unprocessed := []signature.Attribute{
		{Key: "unknownKey", Critical: true, Value: "unknownValue"},
		{Key: "anotherKey", Critical: true, Value: "anotherValue"},
	}
	tests := []struct {
		name            string
		unprocessed     []signature.Attribute
		processed       []interface{}
		pluginName      string
		wantErrContains string
	}{
		{
			name:        "nothing to process",
			unprocessed: nil,
			processed:   nil,
		},
		{
			name:            "unprocessed attribute and no plugin",
			unprocessed:     unprocessed,
			processed:       nil,
			wantErrContains: `extended critical attribute "unknownKey" was not processed: notation has no built-in handler for it and the signature does not specify a verification plugin to process it`,
		},
		{
			name:            "unprocessed attribute and plugin did not report it",
			unprocessed:     unprocessed,
			processed:       []interface{}{"unknownKey"},
			pluginName:      "plugin-name",
			wantErrContains: `extended critical attribute "anotherKey" was not processed by the verification plugin "plugin-name"`,
		},
		{
			name:        "all attributes processed by plugin",
			unprocessed: unprocessed,
			processed:   []interface{}{"unknownKey", "anotherKey"},
			pluginName:  "plugin-name",
		},
		{
			name:        "plugin may also report attributes notation handled itself",
			unprocessed: unprocessed[:1],
			processed:   []interface{}{"unknownKey", "someOtherKey"},
			pluginName:  "plugin-name",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := verifyProcessedCriticalExtendedAttributes(tt.unprocessed, tt.processed, tt.pluginName)
			if tt.wantErrContains == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected an error, got nil")
			}
			if !strings.Contains(err.Error(), tt.wantErrContains) {
				t.Fatalf("expected error containing %q, got %q", tt.wantErrContains, err.Error())
			}
		})
	}
}

func TestExtendedCriticalAttributesEndToEnd(t *testing.T) {
	leaf := testhelper.GetRSALeafCertificate()
	root := testhelper.GetRSARootCertificate()
	x509TrustStore := &staticTrustStore{certs: []*x509.Certificate{root.Cert}}

	policyDocument := trustpolicy.OCIDocument{
		Version: "1.0",
		TrustPolicies: []trustpolicy.OCITrustPolicy{
			{
				Name:           "test-statement-name",
				RegistryScopes: []string{"*"},
				SignatureVerification: trustpolicy.SignatureVerification{
					VerificationLevel: trustpolicy.LevelStrict.Name,
					// skip revocation so that no network access is needed
					Override: map[trustpolicy.ValidationType]trustpolicy.ValidationAction{
						trustpolicy.TypeRevocation: trustpolicy.ActionSkip,
					},
				},
				TrustStores:       []string{"ca:test-store"},
				TrustedIdentities: []string{"*"},
			},
		},
	}

	opts := notation.VerifierVerifyOptions{
		ArtifactReference:  mock.SampleArtifactUri,
		SignatureMediaType: jws.MediaTypeEnvelope,
	}

	newVerifier := func(pm *mock.PluginManager) *verifier {
		v, err := NewVerifierWithOptions(x509TrustStore, VerifierOptions{
			OCITrustPolicy: &policyDocument,
			PluginManager:  pm,
		})
		if err != nil {
			t.Fatalf("unexpected error while creating verifier: %v", err)
		}
		return v
	}

	// noPlugin rejects plugin use, ensuring notation never invokes one.
	noPlugin := &mock.PluginManager{
		GetPluginError: errors.New("plugin must not be invoked"),
	}

	t.Run("critical unknown attribute without plugin fails closed", func(t *testing.T) {
		sigBlob := signTestEnvelope(t, signature.SigningSchemeX509, leaf, []signature.Attribute{
			{Key: "unknownKey", Critical: true, Value: "unknownValue"},
		})
		v := newVerifier(noPlugin)
		outcome, err := v.Verify(context.Background(), mock.ImageDescriptor, sigBlob, opts)
		if err == nil || outcome.Error == nil {
			t.Fatalf("verification must fail when an unknown critical extended attribute cannot be processed")
		}
		want := `extended critical attribute "unknownKey" was not processed: notation has no built-in handler for it and the signature does not specify a verification plugin to process it`
		if err.Error() != want {
			t.Fatalf("expected error %q, got %q", want, err.Error())
		}
	})

	t.Run("non-critical unknown attribute passes", func(t *testing.T) {
		sigBlob := signTestEnvelope(t, signature.SigningSchemeX509, leaf, []signature.Attribute{
			{Key: "unknownKey", Critical: false, Value: "unknownValue"},
		})
		v := newVerifier(noPlugin)
		if _, err := v.Verify(context.Background(), mock.ImageDescriptor, sigBlob, opts); err != nil {
			t.Fatalf("verification must not fail for a non-critical unknown attribute: %v", err)
		}
	})

	t.Run("plugin min version without plugin name fails closed", func(t *testing.T) {
		sigBlob := signTestEnvelope(t, signature.SigningSchemeX509, leaf, []signature.Attribute{
			{Key: HeaderVerificationPluginMinVersion, Critical: true, Value: "1.0.0"},
		})
		v := newVerifier(noPlugin)
		outcome, err := v.Verify(context.Background(), mock.ImageDescriptor, sigBlob, opts)
		if err == nil || outcome.Error == nil {
			t.Fatalf("verification must fail when the plugin minimum version attribute cannot be processed")
		}
		want := `extended critical attribute "io.cncf.notary.verificationPluginMinVersion" was not processed`
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("expected error containing %q, got %q", want, err.Error())
		}
	})

	t.Run("critical unknown attribute processed by plugin passes", func(t *testing.T) {
		sigBlob := signTestEnvelope(t, signature.SigningSchemeX509, leaf, []signature.Attribute{
			{Key: HeaderVerificationPlugin, Critical: true, Value: "plugin-name"},
			{Key: "unknownKey", Critical: true, Value: "unknownValue"},
		})
		pm := &mock.PluginManager{
			PluginCapabilities: []proto.Capability{proto.CapabilityTrustedIdentityVerifier},
			PluginRunnerExecuteResponse: &proto.VerifySignatureResponse{
				VerificationResults: map[proto.Capability]*proto.VerificationResult{
					proto.CapabilityTrustedIdentityVerifier: {Success: true},
				},
				ProcessedAttributes: []interface{}{"unknownKey"},
			},
		}
		v := newVerifier(pm)
		if _, err := v.Verify(context.Background(), mock.ImageDescriptor, sigBlob, opts); err != nil {
			t.Fatalf("verification must succeed when the plugin processed the critical attribute: %v", err)
		}
	})

	t.Run("plugin fails to process critical unknown attribute", func(t *testing.T) {
		sigBlob := signTestEnvelope(t, signature.SigningSchemeX509, leaf, []signature.Attribute{
			{Key: HeaderVerificationPlugin, Critical: true, Value: "plugin-name"},
			{Key: "unknownKey", Critical: true, Value: "unknownValue"},
		})
		pm := &mock.PluginManager{
			PluginCapabilities: []proto.Capability{proto.CapabilityTrustedIdentityVerifier},
			PluginRunnerExecuteResponse: &proto.VerifySignatureResponse{
				VerificationResults: map[proto.Capability]*proto.VerificationResult{
					proto.CapabilityTrustedIdentityVerifier: {Success: true},
				},
				ProcessedAttributes: []interface{}{},
			},
		}
		v := newVerifier(pm)
		outcome, err := v.Verify(context.Background(), mock.ImageDescriptor, sigBlob, opts)
		if err == nil || outcome.Error == nil {
			t.Fatalf("verification must fail when the plugin does not process the critical attribute")
		}
		want := `extended critical attribute "unknownKey" was not processed by the verification plugin "plugin-name"`
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("expected error containing %q, got %q", want, err.Error())
		}
	})

	t.Run("plugin may report additional attributes", func(t *testing.T) {
		sigBlob := signTestEnvelope(t, signature.SigningSchemeX509, leaf, []signature.Attribute{
			{Key: HeaderVerificationPlugin, Critical: true, Value: "plugin-name"},
			{Key: "unknownKey", Critical: true, Value: "unknownValue"},
		})
		pm := &mock.PluginManager{
			PluginCapabilities: []proto.Capability{proto.CapabilityTrustedIdentityVerifier},
			PluginRunnerExecuteResponse: &proto.VerifySignatureResponse{
				VerificationResults: map[proto.Capability]*proto.VerificationResult{
					proto.CapabilityTrustedIdentityVerifier: {Success: true},
				},
				ProcessedAttributes: []interface{}{"unknownKey", "neverDelegated"},
			},
		}
		v := newVerifier(pm)
		if _, err := v.Verify(context.Background(), mock.ImageDescriptor, sigBlob, opts); err != nil {
			t.Fatalf("verification must not fail just because the plugin reported extra attributes: %v", err)
		}
	})

	t.Run("plugin capability skipped by policy still fails closed", func(t *testing.T) {
		sigBlob := signTestEnvelope(t, signature.SigningSchemeX509, leaf, []signature.Attribute{
			{Key: HeaderVerificationPlugin, Critical: true, Value: "plugin-name"},
			{Key: "unknownKey", Critical: true, Value: "unknownValue"},
		})
		// The only plugin capability is revocation, which the trust policy
		// skips, so the plugin is never invoked and cannot process the
		// attribute. Verification must still fail closed.
		pm := &mock.PluginManager{
			PluginCapabilities:       []proto.Capability{proto.CapabilityRevocationCheckVerifier},
			PluginRunnerExecuteError: errors.New("plugin must not be invoked when all its capabilities are skipped"),
		}
		v := newVerifier(pm)
		outcome, err := v.Verify(context.Background(), mock.ImageDescriptor, sigBlob, opts)
		if err == nil || outcome.Error == nil {
			t.Fatalf("verification must fail closed when no capability remains to process the critical attribute")
		}
		if err.Error() == "failed to verify with plugin plugin-name: plugin must not be invoked when all its capabilities are skipped" {
			t.Fatalf("plugin must not be invoked when all its capabilities are skipped")
		}
		want := `extended critical attribute "unknownKey" was not processed`
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("expected error containing %q, got %q", want, err.Error())
		}
	})
}

// signTestEnvelope creates a JWS signature envelope signed by the given leaf
// certificate carrying the given extended signed attributes.
func signTestEnvelope(t *testing.T, scheme signature.SigningScheme, leaf testhelper.RSACertTuple, attrs []signature.Attribute) []byte {
	t.Helper()

	signer, err := signature.NewLocalSigner(
		[]*x509.Certificate{leaf.Cert, testhelper.GetRSARootCertificate().Cert},
		leaf.PrivateKey,
	)
	if err != nil {
		t.Fatalf("unexpected error while creating signer: %v", err)
	}
	payload, err := json.Marshal(envelope.Payload{TargetArtifact: mock.ImageDescriptor})
	if err != nil {
		t.Fatalf("unexpected error while marshaling payload: %v", err)
	}
	env, err := signature.NewEnvelope(jws.MediaTypeEnvelope)
	if err != nil {
		t.Fatalf("unexpected error while creating envelope: %v", err)
	}
	sigBlob, err := env.Sign(&signature.SignRequest{
		Payload: signature.Payload{
			ContentType: envelope.MediaTypePayloadV1,
			Content:     payload,
		},
		Signer:                   signer,
		SigningTime:              time.Now(),
		ExtendedSignedAttributes: attrs,
		SigningScheme:            scheme,
		SigningAgent:             "notation-go-test",
	})
	if err != nil {
		t.Fatalf("unexpected error while signing test envelope: %v", err)
	}
	return sigBlob
}

// staticTrustStore implements [truststore.X509TrustStore] returning a fixed set
// of certificates for every trust store.
type staticTrustStore struct {
	certs []*x509.Certificate
}

func (s *staticTrustStore) GetCertificates(_ context.Context, _ truststore.Type, _ string) ([]*x509.Certificate, error) {
	return s.certs, nil
}
