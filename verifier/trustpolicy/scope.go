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
	"fmt"
	"regexp"
	"strings"

	"github.com/notaryproject/notation-go/internal/trustpolicy"
)

// ensureMessage describes the accepted format of a registry scope.
const ensureMessage = "make sure it is a fully qualified repository without the scheme, protocol or tag. For example domain.com/my/repository or a local scope like local/myOCILayout"

// domainRegexp and repositoryRegexp are adapted from the distribution
// implementation:
// https://github.com/distribution/distribution/blob/main/reference/regexp.go#L31
var (
	domainRegexp = regexp.MustCompile(`^(?:[a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9])(?:(?:\.(?:[a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9]))+)?(?::[0-9]+)?$`)
	// repositoryRegexp matches a complete repository path including its path
	// separators.
	repositoryRegexp = regexp.MustCompile(`^[a-z0-9]+(?:(?:(?:[._]|__|[-]*)[a-z0-9]+)+)?(?:(?:/[a-z0-9]+(?:(?:(?:[._]|__|[-]*)[a-z0-9]+)+)?)+)?$`)
	// scopeNameComponentRegexp matches a single repository path component. A
	// component is either a bare wildcard level ("*") or a regular repository
	// name component; partial-component wildcards (for example "repo*") are
	// intentionally rejected to keep matching unambiguous.
	scopeNameComponentRegexp = regexp.MustCompile(`^[a-z0-9]+(?:(?:[._]|__|[-]*)[a-z0-9]+)*$|^\*$`)
)

// registryScope is the normalized form of an OCI registry scope.
//
// A scope such as "registry.example.com/my/repo" is split into the registry
// (host[:port]) and the repository path components. A trailing "*" component
// marks a wildcard level that matches one or more repository components.
type registryScope struct {
	// registry is the normalized registry host[:port], lower-cased because
	// DNS names and ports are case-insensitive.
	registry string

	// repository is the normalized list of lower-cased repository path
	// components. An empty repository means the global wildcard scope "*".
	repository []string

	// wildcard reports whether the scope ends with a wildcard level.
	wildcard bool

	// raw is the original scope string, retained for error messages.
	raw string
}

// isGlobalWildcard reports whether the scope is the global wildcard "*".
func (s registryScope) isGlobalWildcard() bool {
	return s.raw == trustpolicy.Wildcard
}

// normalizedArtifact is the normalized form of an OCI artifact reference.
type normalizedArtifact struct {
	// registry is the normalized registry host[:port].
	registry string

	// repository is the normalized list of repository path components,
	// without any tag or digest.
	repository []string
}

// specificity ranks how specific a scope is. Higher values always win so a
// narrow statement (for example an exact repository match) can never be
// shadowed by a broader statement (for example a registry-level wildcard or
// the global "*" wildcard).
func (s registryScope) specificity() int {
	switch {
	case s.isGlobalWildcard():
		return 0
	case s.wildcard:
		// one point per fixed repository component plus one for the
		// registry. A registry-level wildcard ("domain.com/*") therefore
		// ranks above the global wildcard but below any repository-scoped
		// rule.
		return 1 + len(s.repository)
	default:
		// exact matches rank above wildcard scopes with the same number of
		// path components.
		return 2 + len(s.repository)
	}
}

// matches reports whether the scope applies to the given artifact. Matching is
// performed on normalized components, hence it is case-insensitive for the
// registry host and insensitive to trailing slashes, tags and digest
// references.
func (s registryScope) matches(artifact normalizedArtifact) bool {
	if s.isGlobalWildcard() {
		return true
	}
	if s.registry != artifact.registry {
		// registries are matched distinctly: a scope on registry A can
		// never apply to an artifact on registry B, not even through a
		// wildcard level.
		return false
	}
	if s.wildcard {
		// a wildcard level matches the component(s) following the fixed
		// prefix, so the artifact must have strictly more repository
		// components than the scope's fixed prefix.
		if len(artifact.repository) <= len(s.repository) {
			return false
		}
		for i, component := range s.repository {
			if component != artifact.repository[i] {
				return false
			}
		}
		return true
	}
	// exact scope: every repository component must match.
	if len(artifact.repository) != len(s.repository) {
		return false
	}
	for i, component := range s.repository {
		if component != artifact.repository[i] {
			return false
		}
	}
	return true
}

// parseRegistryScope normalizes and validates a registry scope.
//
// Supported forms are:
//   - "*"                                   (global wildcard)
//   - "domain.com/repository"               (exact scope)
//   - "domain.com/repository/*"             (namespace wildcard level)
//   - "local/myOCILayout"                   (local scope)
func parseRegistryScope(scope string) (registryScope, error) {
	if scope == trustpolicy.Wildcard {
		return registryScope{raw: scope}, nil
	}

	// the original (un-normalized) scope is rejected when it contains
	// characters that normalization cannot make unambiguous.
	if err := validateRegistryScopeFormat(scope); err != nil {
		return registryScope{}, err
	}

	registry, repositoryPath, _ := strings.Cut(scope, "/")
	normalized := registryScope{
		registry: strings.ToLower(registry),
		raw:      scope,
	}
	for _, component := range strings.Split(repositoryPath, "/") {
		if component == "*" {
			// a bare "*" path component is a wildcard level spanning one or
			// more repository components. It must be the final component,
			// which is enforced by validateRegistryScopeFormat above.
			normalized.wildcard = true
			continue
		}
		if normalized.wildcard {
			// nothing may follow a wildcard level.
			return registryScope{}, fmt.Errorf("registry scope %q with wild card(s) is not valid, %s", scope, ensureMessage)
		}
		normalized.repository = append(normalized.repository, strings.ToLower(component))
	}
	if len(normalized.repository) == 0 && !normalized.wildcard {
		return registryScope{}, fmt.Errorf("registry scope %q is not valid, %s", scope, ensureMessage)
	}
	return normalized, nil
}

// parseArtifactReference normalizes an OCI artifact reference into its registry
// and repository components. The digest (and, when present, the tag) is
// discarded because trust policy selection is based on the repository only.
func parseArtifactReference(artifactReference string) (normalizedArtifact, error) {
	reference := artifactReference

	// strip the digest reference. Only the last "@" delimiter is considered
	// so an additional "@" inside the repository part fails validation below
	// instead of being silently accepted.
	if i := strings.LastIndex(reference, "@"); i >= 0 {
		reference = reference[:i]
	}

	// strip an optional tag. A ":" after the first "/" belongs to the tag;
	// a ":" before the first "/" is a registry port.
	if i := strings.Index(reference, "/"); i >= 0 {
		if j := strings.Index(reference[i+1:], ":"); j >= 0 {
			reference = reference[:i+1+j]
		}
	}

	// normalize away trailing slashes and redundant empty path components.
	reference = strings.TrimRight(reference, "/")
	if reference == "" {
		return normalizedArtifact{}, invalidArtifactReferenceError(artifactReference)
	}
	registry, repositoryPath, found := strings.Cut(reference, "/")
	if !found || registry == "" || repositoryPath == "" {
		return normalizedArtifact{}, invalidArtifactReferenceError(artifactReference)
	}
	parsed := normalizedArtifact{registry: strings.ToLower(registry)}
	for _, component := range strings.Split(repositoryPath, "/") {
		if component == "" {
			return normalizedArtifact{}, invalidArtifactReferenceError(artifactReference)
		}
		parsed.repository = append(parsed.repository, strings.ToLower(component))
	}
	if !domainRegexp.MatchString(registry) || !repositoryRegexp.MatchString(repositoryPath) {
		return normalizedArtifact{}, invalidArtifactReferenceError(artifactReference)
	}
	return parsed, nil
}

func invalidArtifactReferenceError(artifactReference string) error {
	return fmt.Errorf("artifact URI %q could not be parsed, make sure it is the fully qualified oci artifact URI without the scheme/protocol. e.g domain.com:80/my/repository@sha256:digest", artifactReference)
}

// validateRegistryScopeFormat validates if a scope follows the format defined
// in the distribution specification, extended with an optional trailing
// wildcard level.
func validateRegistryScopeFormat(scope string) error {
	errorMessage := "registry scope %q is not valid, " + ensureMessage
	errorWildCardMessage := "registry scope %q with wild card(s) is not valid, " + ensureMessage

	domain, repository, found := strings.Cut(scope, "/")
	if !found || domain == "" || strings.Contains(domain, "*") {
		// a wildcard may only appear as a repository path level, never as
		// the registry host or outside a repository path.
		if strings.Contains(scope, "*") {
			return fmt.Errorf(errorWildCardMessage, scope)
		}
		return fmt.Errorf(errorMessage, scope)
	}
	if repository == "" || !domainRegexp.MatchString(domain) {
		return fmt.Errorf(errorMessage, scope)
	}

	components := strings.Split(repository, "/")
	for index, component := range components {
		if component == "" {
			return fmt.Errorf(errorMessage, scope)
		}
		if component == "*" {
			// a wildcard level is only valid as the final component.
			if index != len(components)-1 {
				return fmt.Errorf(errorWildCardMessage, scope)
			}
			continue
		}
		if strings.Contains(component, "*") || !scopeNameComponentRegexp.MatchString(component) {
			// partial-component wildcards and characters outside the
			// distribution repository grammar are both rejected here.
			if strings.Contains(component, "*") {
				return fmt.Errorf(errorWildCardMessage, scope)
			}
			return fmt.Errorf(errorMessage, scope)
		}
	}
	return nil
}
