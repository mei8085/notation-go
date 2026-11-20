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

package trustpolicy

import (
	"errors"
	"fmt"
	"strings"

	"github.com/notaryproject/notation-go/dir"
	set "github.com/notaryproject/notation-go/internal/container"
	"github.com/notaryproject/notation-go/internal/slices"
	"github.com/notaryproject/notation-go/internal/trustpolicy"
)

// OCIDocument represents a trustpolicy.oci.json document for OCI artifacts
type OCIDocument struct {
	// Version of the policy document
	Version string `json:"version"`

	// TrustPolicies include each policy statement
	TrustPolicies []OCITrustPolicy `json:"trustPolicies"`
}

// OCITrustPolicy represents a policy statement in the OCI trust policy document
type OCITrustPolicy struct {
	// Name of the policy statement
	Name string `json:"name"`

	// SignatureVerification setting for this policy statement
	SignatureVerification SignatureVerification `json:"signatureVerification"`

	// TrustStores this policy statement uses
	TrustStores []string `json:"trustStores"`

	// TrustedIdentities this policy statement pins
	TrustedIdentities []string `json:"trustedIdentities"`

	// RegistryScopes that this policy statement affects
	RegistryScopes []string `json:"registryScopes"`
}

// Document represents a trustPolicy.json document
//
// Deprecated: Document exists for historical compatibility and
// should not be used. To create OCI Document, use [OCIDocument].
type Document = OCIDocument

// TrustPolicy represents a policy statement in the policy document
//
// Deprecated: TrustPolicy exists for historical compatibility and
// should not be used. To create OCI TrustPolicy, use [OCITrustPolicy].
type TrustPolicy = OCITrustPolicy

// LoadDocument loads a trust policy document from a local file system
//
// Deprecated: LoadDocument function exists for historical compatibility and
// should not be used. To load OCI Document, use [LoadOCIDocument] function.
var LoadDocument = LoadOCIDocument

var supportedOCIPolicyVersions = []string{"1.0"}

// LoadOCIDocument retrieves a trust policy document from the local file system.
// It attempts to read from [dir.PathOCITrustPolicy] first; if not found,
// it tries [dir.PathTrustPolicy].
// If both dir.PathOCITrustPolicy and dir.PathTrustPolicy exist,
// dir.PathOCITrustPolicy will be read.
func LoadOCIDocument() (*OCIDocument, error) {
	var doc OCIDocument

	// attempt to load the document from dir.PathOCITrustPolicy
	if err := getDocument(dir.PathOCITrustPolicy, &doc); err != nil {
		// if the document is not found at the first path, try the second path
		if errors.As(err, &errPolicyNotExist{}) {
			if err := getDocument(dir.PathTrustPolicy, &doc); err != nil {
				return nil, err
			}
			return &doc, nil
		}

		// if an error occurred other than the document not found, return it
		return nil, err
	}
	return &doc, nil
}

// Validate validates a policy document according to its version's rule set.
// if any rule is violated, returns an error
func (policyDoc *OCIDocument) Validate() error {
	// sanity check
	if policyDoc == nil {
		return errors.New("oci trust policy document cannot be nil")
	}

	// Validate Version
	if policyDoc.Version == "" {
		return errors.New("oci trust policy document has empty version, version must be specified")
	}
	if !slices.Contains(supportedOCIPolicyVersions, policyDoc.Version) {
		return fmt.Errorf("oci trust policy document uses unsupported version %q", policyDoc.Version)
	}

	// Validate the policy according to 1.0 rules
	if len(policyDoc.TrustPolicies) == 0 {
		return errors.New("oci trust policy document can not have zero trust policy statements")
	}
	policyNames := set.New[string]()
	for _, statement := range policyDoc.TrustPolicies {
		// Verify unique policy statement names across the policy document
		if policyNames.Contains(statement.Name) {
			return fmt.Errorf("multiple oci trust policy statements use the same name %q, statement names must be unique", statement.Name)
		}
		if err := validatePolicyCore(statement.Name, statement.SignatureVerification, statement.TrustStores, statement.TrustedIdentities); err != nil {
			return fmt.Errorf("oci trust policy: %w", err)
		}
		policyNames.Add(statement.Name)
	}

	// Verify registry scopes are valid
	if err := validateRegistryScopes(policyDoc); err != nil {
		return err
	}
	return nil
}

// GetApplicableTrustPolicy returns a pointer to the deep copied [OCITrustPolicy]
// statement that applies to the given artifact reference. If no applicable
// trust policy is found, returns an error.
//
// Registry scopes are normalized before matching, so selection is
// case-insensitive for the registry host and repository, ignores trailing
// slashes as well as the artifact's tag and digest, and distinguishes the
// registry, namespace and repository levels. Wildcard levels (for example
// "registry.example.com/team/*") are supported: the most specific matching
// scope always wins, so a narrower statement (including a deny/strict one) can
// never be overridden by a broader wildcard statement or the global "*"
// wildcard.
// see https://github.com/notaryproject/specifications/tree/9c81dc773508dedc5a81c02c8d805de04f65050b/specs/trust-store-trust-policy.md#selecting-a-trust-policy-based-on-artifact-uri
func (policyDoc *OCIDocument) GetApplicableTrustPolicy(artifactReference string) (*OCITrustPolicy, error) {
	artifact, err := parseArtifactReference(artifactReference)
	if err != nil {
		return nil, err
	}

	var applicablePolicy *OCITrustPolicy
	applicableSpecificity := -1
	for i := range policyDoc.TrustPolicies {
		policyStatement := &policyDoc.TrustPolicies[i]
		matchedSpecificity := -1
		for _, rawScope := range policyStatement.RegistryScopes {
			scope, err := parseRegistryScope(rawScope)
			if err != nil {
				// the document is expected to be validated before use; an
				// invalid scope simply cannot match the artifact.
				continue
			}
			if scope.matches(artifact) && scope.specificity() > matchedSpecificity {
				matchedSpecificity = scope.specificity()
			}
		}
		if matchedSpecificity < 0 {
			continue
		}
		if matchedSpecificity > applicableSpecificity {
			// a more specific match always takes precedence over a broader
			// match, regardless of statement order in the document.
			applicablePolicy = policyStatement.clone()
			applicableSpecificity = matchedSpecificity
		}
	}
	if applicablePolicy != nil {
		return applicablePolicy, nil
	}
	return nil, fmt.Errorf("artifact %q has no applicable oci trust policy statement. Trust policy applicability for a given artifact is determined by registryScopes. To create a trust policy, see: %s", artifactReference, trustPolicyLink)
}

// clone returns a pointer to the deep copied [OCITrustPolicy]
func (t *OCITrustPolicy) clone() *OCITrustPolicy {
	return &OCITrustPolicy{
		Name:                  t.Name,
		SignatureVerification: t.SignatureVerification,
		TrustedIdentities:     append([]string(nil), t.TrustedIdentities...),
		TrustStores:           append([]string(nil), t.TrustStores...),
		RegistryScopes:        append([]string(nil), t.RegistryScopes...),
	}
}

// validateRegistryScopes validates if the policy document is following the
// Notary Project spec rules for registry scopes
func validateRegistryScopes(policyDoc *OCIDocument) error {
	registryScopeCount := make(map[string]int)
	for _, statement := range policyDoc.TrustPolicies {
		// Verify registry scopes are valid
		if len(statement.RegistryScopes) == 0 {
			return fmt.Errorf("oci trust policy statement %q has zero registry scopes, it must specify registry scopes with at least one value", statement.Name)
		}
		if len(statement.RegistryScopes) > 1 && slices.Contains(statement.RegistryScopes, trustpolicy.Wildcard) {
			return fmt.Errorf("oci trust policy statement %q uses wildcard registry scope '*', a wildcard scope cannot be used in conjunction with other scope values", statement.Name)
		}
		for _, scope := range statement.RegistryScopes {
			normalized, err := parseRegistryScope(scope)
			if err != nil {
				return err
			}
			// normalize equivalent scopes (e.g. differing only by case) so
			// duplicates are detected regardless of how they are written.
			registryScopeCount[normalizedRegistryScopeKey(normalized)]++
		}
	}

	// Verify one policy statement per registry scope
	for key := range registryScopeCount {
		if registryScopeCount[key] > 1 {
			return fmt.Errorf("registry scope %q is present in multiple oci trust policy statements, one registry scope value can only be associated with one statement", key)
		}
	}

	// No error
	return nil
}

// normalizedRegistryScopeKey returns a canonical string representation of a
// normalized registry scope, suitable for duplicate detection.
func normalizedRegistryScopeKey(scope registryScope) string {
	if scope.isGlobalWildcard() {
		return trustpolicy.Wildcard
	}
	key := scope.registry + "/" + strings.Join(scope.repository, "/")
	if scope.wildcard {
		key += "/*"
	}
	return key
}
