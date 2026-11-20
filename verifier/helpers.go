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
	"errors"
	"fmt"
	"strings"

	"github.com/notaryproject/notation-core-go/signature"
	"github.com/notaryproject/notation-go"
	set "github.com/notaryproject/notation-go/internal/container"
	notationsemver "github.com/notaryproject/notation-go/internal/semver"
	"github.com/notaryproject/notation-go/internal/slices"
	"github.com/notaryproject/notation-go/verifier/trustpolicy"
	"github.com/notaryproject/notation-go/verifier/truststore"
)

const (
	// HeaderVerificationPlugin specifies the name of the verification plugin
	// that should be used to verify the signature.
	HeaderVerificationPlugin = "io.cncf.notary.verificationPlugin"

	// HeaderVerificationPluginMinVersion specifies the minimum version of the
	// verification plugin that should be used to verify the signature.
	HeaderVerificationPluginMinVersion = "io.cncf.notary.verificationPluginMinVersion"
)

// VerificationPluginHeaders specifies headers of a verification plugin.
//
// Notation has a built-in handler for each of these extended attributes, so
// they never need to be delegated to a verification plugin. Every other
// extended attribute marked critical MUST be processed by a verification
// plugin, otherwise signature verification MUST fail.
var VerificationPluginHeaders = []string{
	HeaderVerificationPlugin,
	HeaderVerificationPluginMinVersion,
}

var errExtendedAttributeNotExist = errors.New("extended attribute not exist")

func loadX509TrustStores(ctx context.Context, scheme signature.SigningScheme, policyName string, trustStores []string, x509TrustStore truststore.X509TrustStore) ([]*x509.Certificate, error) {
	var typeToLoad truststore.Type
	switch scheme {
	case signature.SigningSchemeX509:
		typeToLoad = truststore.TypeCA
	case signature.SigningSchemeX509SigningAuthority:
		typeToLoad = truststore.TypeSigningAuthority
	default:
		return nil, truststore.TrustStoreError{Msg: fmt.Sprintf("error while loading the trust store, unrecognized signing scheme %q", scheme)}
	}
	return loadX509TrustStoresWithType(ctx, typeToLoad, policyName, trustStores, x509TrustStore)
}

// isCriticalFailure checks whether a [notation.ValidationResult] fails the
// entire signature verification workflow.
// signature verification workflow is considered failed if there is a
// ValidationResult with "Enforced" as the action but the result was
// unsuccessful.
func isCriticalFailure(result *notation.ValidationResult) bool {
	return result.Action == trustpolicy.ActionEnforce && result.Error != nil
}

// notationHandledExtendedAttributes returns the set of extended attribute keys
// that notation itself knows how to process. Every other extended attribute
// marked critical MUST be processed by a verification plugin.
func notationHandledExtendedAttributes(signerInfo *signature.SignerInfo) map[string]bool {
	handled := map[string]bool{HeaderVerificationPlugin: true}
	// The minimum version attribute is only meaningful, and therefore only
	// handled by notation, when the verification plugin attribute is present.
	if _, err := signerInfo.ExtendedAttribute(HeaderVerificationPlugin); err == nil {
		handled[HeaderVerificationPluginMinVersion] = true
	}
	return handled
}

// getUnprocessedCriticalExtendedAttributes returns the extended attributes that
// are marked critical but have no built-in handler in notation. Those
// attributes MUST be processed by a verification plugin, otherwise signature
// verification MUST fail.
//
// Extended attributes that are NOT marked critical are informational: they do
// not influence signature verification, are not required to be processed and
// are therefore not returned.
//
// A critical extended attribute whose key is not a string is malformed:
// notation cannot name it in the plugin contract, so it can never be processed.
// An error is returned in that case and signature verification MUST fail.
func getUnprocessedCriticalExtendedAttributes(signerInfo *signature.SignerInfo) ([]signature.Attribute, error) {
	handled := notationHandledExtendedAttributes(signerInfo)
	var unprocessed []signature.Attribute
	for _, attr := range signerInfo.SignedAttributes.ExtendedAttributes {
		if !attr.Critical {
			// informational attribute, ignore it
			continue
		}
		key, ok := attr.Key.(string)
		if !ok {
			return nil, fmt.Errorf("extended critical attribute with key %v is malformed: unsupported key type %T, only string keys can be processed", attr.Key, attr.Key)
		}
		if handled[key] {
			// notation has a built-in handler for this attribute
			continue
		}
		unprocessed = append(unprocessed, attr)
	}
	return unprocessed, nil
}

// verifyProcessedCriticalExtendedAttributes verifies that every critical
// extended attribute without a built-in handler was processed by a verification
// plugin holding a capability. Verification MUST fail if any such attribute was
// left unprocessed.
func verifyProcessedCriticalExtendedAttributes(unprocessed []signature.Attribute, processedAttributes []interface{}, verificationPluginName string) error {
	for _, attr := range unprocessed {
		// getUnprocessedCriticalExtendedAttributes only returns attributes with
		// a string key, so the assertion below is safe.
		key := attr.Key.(string)
		if slices.ContainsAny(processedAttributes, key) {
			continue
		}
		if verificationPluginName == "" {
			return fmt.Errorf("extended critical attribute %q was not processed: notation has no built-in handler for it and the signature does not specify a verification plugin to process it", key)
		}
		return fmt.Errorf("extended critical attribute %q was not processed by the verification plugin %q (all extended critical attributes must be processed by the verification plugin)", key, verificationPluginName)
	}
	return nil
}

// extractCriticalStringExtendedAttribute extracts a critical string Extended
// attribute from a signer.
func extractCriticalStringExtendedAttribute(signerInfo *signature.SignerInfo, key string) (string, error) {
	attr, err := signerInfo.ExtendedAttribute(key)
	// not exist
	if err != nil {
		return "", errExtendedAttributeNotExist
	}
	// not critical
	if !attr.Critical {
		return "", fmt.Errorf("%v is not a critical Extended attribute", key)
	}
	// not string
	val, ok := attr.Value.(string)
	if !ok {
		return "", fmt.Errorf("%v from extended attribute is not a string", key)
	}
	return val, nil
}

// getVerificationPlugin get plugin name from the Extended attributes.
func getVerificationPlugin(signerInfo *signature.SignerInfo) (string, error) {
	name, err := extractCriticalStringExtendedAttribute(signerInfo, HeaderVerificationPlugin)
	if err != nil {
		return "", err
	}
	// not an empty string
	if strings.TrimSpace(name) == "" {
		return "", fmt.Errorf("%v from extended attribute is an empty string", HeaderVerificationPlugin)
	}
	return name, nil
}

// getVerificationPlugin get plugin version from the Extended attributes.
func getVerificationPluginMinVersion(signerInfo *signature.SignerInfo) (string, error) {
	version, err := extractCriticalStringExtendedAttribute(signerInfo, HeaderVerificationPluginMinVersion)
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(version) == "" {
		return "", fmt.Errorf("%v from extended attribute is an empty string", HeaderVerificationPluginMinVersion)
	}
	if !notationsemver.IsValid(version) {
		return "", fmt.Errorf("%v from extended attribute is not a valid SemVer", HeaderVerificationPluginMinVersion)
	}
	return version, nil
}

func loadX509TSATrustStores(ctx context.Context, scheme signature.SigningScheme, policyName string, trustStores []string, x509TrustStore truststore.X509TrustStore) ([]*x509.Certificate, error) {
	var typeToLoad truststore.Type
	switch scheme {
	case signature.SigningSchemeX509:
		typeToLoad = truststore.TypeTSA
	default:
		return nil, truststore.TrustStoreError{Msg: fmt.Sprintf("error while loading the TSA trust store, signing scheme must be notary.x509, but got %s", scheme)}
	}
	return loadX509TrustStoresWithType(ctx, typeToLoad, policyName, trustStores, x509TrustStore)
}

func loadX509TrustStoresWithType(ctx context.Context, trustStoreType truststore.Type, policyName string, trustStores []string, x509TrustStore truststore.X509TrustStore) ([]*x509.Certificate, error) {
	processedStoreSet := set.New[string]()
	var certificates []*x509.Certificate
	for _, trustStore := range trustStores {
		if processedStoreSet.Contains(trustStore) {
			// we loaded this trust store already
			continue
		}

		storeType, name, found := strings.Cut(trustStore, ":")
		if !found {
			return nil, truststore.TrustStoreError{Msg: fmt.Sprintf("error while loading the trust store, trust policy statement %q is missing separator in trust store value %q. The required format is <TrustStoreType>:<TrustStoreName>", policyName, trustStore)}
		}
		if trustStoreType != truststore.Type(storeType) {
			continue
		}

		certs, err := x509TrustStore.GetCertificates(ctx, trustStoreType, name)
		if err != nil {
			return nil, err
		}
		certificates = append(certificates, certs...)
		processedStoreSet.Add(trustStore)
	}
	return certificates, nil
}

// isTSATrustStoreInPolicy checks if tsa trust store is configured in
// trust policy
func isTSATrustStoreInPolicy(policyName string, trustStores []string) (bool, error) {
	for _, trustStore := range trustStores {
		storeType, _, found := strings.Cut(trustStore, ":")
		if !found {
			return false, truststore.TrustStoreError{Msg: fmt.Sprintf("invalid trust policy statement: %q is missing separator in trust store value %q. The required format is <TrustStoreType>:<TrustStoreName>", policyName, trustStore)}
		}
		if truststore.Type(storeType) == truststore.TypeTSA {
			return true, nil
		}
	}
	return false, nil
}
