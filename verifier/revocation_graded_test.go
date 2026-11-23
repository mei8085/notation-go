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
	"testing"
	"time"

	"github.com/notaryproject/notation-core-go/revocation"
	revocationresult "github.com/notaryproject/notation-core-go/revocation/result"
	"github.com/notaryproject/notation-core-go/signature"
	"github.com/notaryproject/notation-core-go/testhelper"
	"github.com/notaryproject/notation-go"
	"github.com/notaryproject/notation-go/log"
	"github.com/notaryproject/notation-go/verifier/trustpolicy"
	pluginframework "github.com/notaryproject/notation-plugin-framework-go/plugin"
)

// scriptedRevocationValidator is a test-only implementation of
// revocation.Validator. It returns a fixed per-certificate result so the
// graded revocation handling can be exercised without network access.
type scriptedRevocationValidator struct {
	// result is reported for every non-root certificate; the root is always
	// reported as NonRevokable.
	result revocationresult.Result

	// err, when non-nil, is returned by ValidateContext instead of results.
	err error

	// callCount counts ValidateContext invocations.
	callCount int
}

func (s *scriptedRevocationValidator) ValidateContext(_ context.Context, opts revocation.ValidateContextOptions) ([]*revocationresult.CertRevocationResult, error) {
	s.callCount++
	if s.err != nil {
		return nil, s.err
	}
	certResults := make([]*revocationresult.CertRevocationResult, len(opts.CertChain))
	for i := range opts.CertChain {
		if i == len(opts.CertChain)-1 {
			certResults[i] = &revocationresult.CertRevocationResult{
				Result: revocationresult.ResultNonRevokable,
				ServerResults: []*revocationresult.ServerResult{{
					Result:           revocationresult.ResultNonRevokable,
					RevocationMethod: revocationresult.RevocationMethodUnknown,
				}},
				RevocationMethod: revocationresult.RevocationMethodUnknown,
			}
			continue
		}
		certResults[i] = &revocationresult.CertRevocationResult{
			Result: s.result,
			ServerResults: []*revocationresult.ServerResult{{
				Result:           s.result,
				Server:           "mock://revocation",
				RevocationMethod: revocationresult.RevocationMethodOCSP,
			}},
			RevocationMethod: revocationresult.RevocationMethodOCSP,
		}
	}
	return certResults, nil
}

// gradedRevocationChain returns a 3-certificate chain used by the graded
// revocation tests. Only the subject names are inspected by the tests.
func gradedRevocationChain() []*x509.Certificate {
	tuples := testhelper.GetRevokableRSAChain(3)
	return []*x509.Certificate{tuples[0].Cert, tuples[1].Cert, tuples[2].Cert}
}

// gradedRevocationOutcome builds a VerificationOutcome carrying the given
// verification level for a signature under notary.x509.signingAuthority.
func gradedRevocationOutcome(chain []*x509.Certificate, level *trustpolicy.VerificationLevel) *notation.VerificationOutcome {
	return &notation.VerificationOutcome{
		EnvelopeContent: &signature.EnvelopeContent{
			SignerInfo: signature.SignerInfo{
				SignedAttributes: signature.SignedAttributes{
					SigningTime:   time.Now(),
					SigningScheme: signature.SigningSchemeX509SigningAuthority,
				},
				CertificateChain: chain,
			},
		},
		VerificationLevel: level,
	}
}

// gradedLevel builds a custom level from the given enforcement map.
func gradedLevel(enforcement map[trustpolicy.ValidationType]trustpolicy.ValidationAction) *trustpolicy.VerificationLevel {
	return &trustpolicy.VerificationLevel{Name: "custom", Enforcement: enforcement}
}

// TestVerifyRevocationGradedActions is the review anchor for the graded
// revocation handling: it pins, for each (outcome, level) pair, the action
// reported on the ValidationResult and whether the check is critical.
func TestVerifyRevocationGradedActions(t *testing.T) {
	chain := gradedRevocationChain()
	leaf := chain[0].Subject.String()

	tests := []struct {
		name string
		// result is the per-cert revocation result returned by the validator.
		result revocationresult.Result
		// level is the verification level under test.
		level *trustpolicy.VerificationLevel
		// wantAction is the action attached to the ValidationResult.
		wantAction trustpolicy.ValidationAction
		// wantErr is the expected error message; empty means success.
		wantErr string
		// wantOutcome is the classified outcome; empty means success.
		wantOutcome trustpolicy.RevocationOutcome
	}{
		{
			name:   "revoked with umbrella enforce",
			result: revocationresult.ResultRevoked,
			level: gradedLevel(map[trustpolicy.ValidationType]trustpolicy.ValidationAction{
				trustpolicy.TypeRevocation: trustpolicy.ActionEnforce,
			}),
			wantAction:  trustpolicy.ActionEnforce,
			wantErr:     fmt.Sprintf("signing certificate with subject %q is revoked", leaf),
			wantOutcome: trustpolicy.RevocationOutcomeRevoked,
		},
		{
			name:   "revoked with umbrella log",
			result: revocationresult.ResultRevoked,
			level: gradedLevel(map[trustpolicy.ValidationType]trustpolicy.ValidationAction{
				trustpolicy.TypeRevocation: trustpolicy.ActionLog,
			}),
			wantAction:  trustpolicy.ActionLog,
			wantErr:     fmt.Sprintf("signing certificate with subject %q is revoked", leaf),
			wantOutcome: trustpolicy.RevocationOutcomeRevoked,
		},
		{
			name:   "unknown with umbrella enforce",
			result: revocationresult.ResultUnknown,
			level: gradedLevel(map[trustpolicy.ValidationType]trustpolicy.ValidationAction{
				trustpolicy.TypeRevocation: trustpolicy.ActionEnforce,
			}),
			wantAction:  trustpolicy.ActionEnforce,
			wantErr:     fmt.Sprintf("signing certificate with subject %q revocation status is unknown", leaf),
			wantOutcome: trustpolicy.RevocationOutcomeUndetermined,
		},
		{
			name:   "unknown with umbrella log",
			result: revocationresult.ResultUnknown,
			level: gradedLevel(map[trustpolicy.ValidationType]trustpolicy.ValidationAction{
				trustpolicy.TypeRevocation: trustpolicy.ActionLog,
			}),
			wantAction:  trustpolicy.ActionLog,
			wantErr:     fmt.Sprintf("signing certificate with subject %q revocation status is unknown", leaf),
			wantOutcome: trustpolicy.RevocationOutcomeUndetermined,
		},
		{
			name:   "revoked graded log overrides umbrella enforce",
			result: revocationresult.ResultRevoked,
			level: gradedLevel(map[trustpolicy.ValidationType]trustpolicy.ValidationAction{
				trustpolicy.TypeRevocation: trustpolicy.ActionEnforce,
				trustpolicy.TypeRevoked:    trustpolicy.ActionLog,
			}),
			wantAction:  trustpolicy.ActionLog,
			wantErr:     fmt.Sprintf("signing certificate with subject %q is revoked", leaf),
			wantOutcome: trustpolicy.RevocationOutcomeRevoked,
		},
		{
			name:   "revoked graded enforce overrides umbrella log",
			result: revocationresult.ResultRevoked,
			level: gradedLevel(map[trustpolicy.ValidationType]trustpolicy.ValidationAction{
				trustpolicy.TypeRevocation: trustpolicy.ActionLog,
				trustpolicy.TypeRevoked:    trustpolicy.ActionEnforce,
			}),
			wantAction:  trustpolicy.ActionEnforce,
			wantErr:     fmt.Sprintf("signing certificate with subject %q is revoked", leaf),
			wantOutcome: trustpolicy.RevocationOutcomeRevoked,
		},
		{
			name:   "unknown graded log overrides umbrella enforce",
			result: revocationresult.ResultUnknown,
			level: gradedLevel(map[trustpolicy.ValidationType]trustpolicy.ValidationAction{
				trustpolicy.TypeRevocation:            trustpolicy.ActionEnforce,
				trustpolicy.TypeRevocationUnavailable: trustpolicy.ActionLog,
			}),
			wantAction:  trustpolicy.ActionLog,
			wantErr:     fmt.Sprintf("signing certificate with subject %q revocation status is unknown", leaf),
			wantOutcome: trustpolicy.RevocationOutcomeUndetermined,
		},
		{
			name:   "unknown graded enforce overrides umbrella log",
			result: revocationresult.ResultUnknown,
			level: gradedLevel(map[trustpolicy.ValidationType]trustpolicy.ValidationAction{
				trustpolicy.TypeRevocation:            trustpolicy.ActionLog,
				trustpolicy.TypeRevocationUnavailable: trustpolicy.ActionEnforce,
			}),
			wantAction:  trustpolicy.ActionEnforce,
			wantErr:     fmt.Sprintf("signing certificate with subject %q revocation status is unknown", leaf),
			wantOutcome: trustpolicy.RevocationOutcomeUndetermined,
		},
		{
			name:   "revoked does not pick up unavailable override",
			result: revocationresult.ResultRevoked,
			level: gradedLevel(map[trustpolicy.ValidationType]trustpolicy.ValidationAction{
				trustpolicy.TypeRevocation:            trustpolicy.ActionEnforce,
				trustpolicy.TypeRevocationUnavailable: trustpolicy.ActionLog,
			}),
			wantAction:  trustpolicy.ActionEnforce,
			wantErr:     fmt.Sprintf("signing certificate with subject %q is revoked", leaf),
			wantOutcome: trustpolicy.RevocationOutcomeRevoked,
		},
		{
			name:   "unknown does not pick up revoked override",
			result: revocationresult.ResultUnknown,
			level: gradedLevel(map[trustpolicy.ValidationType]trustpolicy.ValidationAction{
				trustpolicy.TypeRevocation: trustpolicy.ActionEnforce,
				trustpolicy.TypeRevoked:    trustpolicy.ActionLog,
			}),
			wantAction:  trustpolicy.ActionEnforce,
			wantErr:     fmt.Sprintf("signing certificate with subject %q revocation status is unknown", leaf),
			wantOutcome: trustpolicy.RevocationOutcomeUndetermined,
		},
		{
			name:   "ok with graded overrides is not affected",
			result: revocationresult.ResultOK,
			level: gradedLevel(map[trustpolicy.ValidationType]trustpolicy.ValidationAction{
				trustpolicy.TypeRevocation:            trustpolicy.ActionEnforce,
				trustpolicy.TypeRevoked:               trustpolicy.ActionLog,
				trustpolicy.TypeRevocationUnavailable: trustpolicy.ActionLog,
			}),
			wantAction: trustpolicy.ActionEnforce,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			validator := &scriptedRevocationValidator{result: tt.result}
			v := &verifier{revocationCodeSigningValidator: validator}
			result := v.verifyRevocation(context.Background(), gradedRevocationOutcome(chain, tt.level))

			if result.Type != trustpolicy.TypeRevocation {
				t.Fatalf("result type = %q, want %q", result.Type, trustpolicy.TypeRevocation)
			}
			if result.Action != tt.wantAction {
				t.Fatalf("result action = %q, want %q", result.Action, tt.wantAction)
			}
			if tt.wantErr == "" {
				if result.Error != nil {
					t.Fatalf("expected success, got error %v", result.Error)
				}
				return
			}
			if result.Error == nil || result.Error.Error() != tt.wantErr {
				t.Fatalf("result error = %v, want %q", result.Error, tt.wantErr)
			}
			var statusErr notation.RevocationStatusError
			if !errors.As(result.Error, &statusErr) {
				t.Fatalf("result error %T is not a notation.RevocationStatusError", result.Error)
			}
			if statusErr.Outcome != tt.wantOutcome {
				t.Fatalf("classified outcome = %q, want %q", statusErr.Outcome, tt.wantOutcome)
			}
			if statusErr.Action != tt.wantAction {
				t.Fatalf("classified action = %q, want %q", statusErr.Action, tt.wantAction)
			}
			if statusErr.Subject != leaf {
				t.Fatalf("classified subject = %q, want %q", statusErr.Subject, leaf)
			}
			if isCriticalFailure(result) != (tt.wantAction == trustpolicy.ActionEnforce) {
				t.Fatalf("isCriticalFailure = %v for action %q", isCriticalFailure(result), tt.wantAction)
			}
		})
	}
}

// TestVerifyRevocationValidatorFailureIsUndetermined pins the failure path:
// when the validator cannot produce any results, the outcome is undetermined
// and the graded "revocationUnavailable" action applies.
func TestVerifyRevocationValidatorFailureIsUndetermined(t *testing.T) {
	chain := gradedRevocationChain()
	level := gradedLevel(map[trustpolicy.ValidationType]trustpolicy.ValidationAction{
		trustpolicy.TypeRevocation:            trustpolicy.ActionEnforce,
		trustpolicy.TypeRevocationUnavailable: trustpolicy.ActionLog,
	})
	v := &verifier{revocationCodeSigningValidator: &scriptedRevocationValidator{err: errors.New("network down")}}
	result := v.verifyRevocation(context.Background(), gradedRevocationOutcome(chain, level))

	wantErr := "unable to check revocation status, err: network down"
	if result.Error == nil || result.Error.Error() != wantErr {
		t.Fatalf("result error = %v, want %q", result.Error, wantErr)
	}
	if result.Action != trustpolicy.ActionLog {
		t.Fatalf("result action = %q, want %q", result.Action, trustpolicy.ActionLog)
	}
	var statusErr notation.RevocationStatusError
	if !errors.As(result.Error, &statusErr) {
		t.Fatalf("result error %T is not a notation.RevocationStatusError", result.Error)
	}
	if statusErr.Outcome != trustpolicy.RevocationOutcomeUndetermined {
		t.Fatalf("classified outcome = %q, want %q", statusErr.Outcome, trustpolicy.RevocationOutcomeUndetermined)
	}
}

// TestVerifyRevocationNilValidatorIsUndetermined pins the failure path when no
// validator is configured: no status can be established, so the graded
// "revocationUnavailable" action applies and the umbrella action is only used
// as a fallback.
func TestVerifyRevocationNilValidatorIsUndetermined(t *testing.T) {
	chain := gradedRevocationChain()

	t.Run("umbrella fallback", func(t *testing.T) {
		level := gradedLevel(map[trustpolicy.ValidationType]trustpolicy.ValidationAction{
			trustpolicy.TypeRevocation: trustpolicy.ActionLog,
		})
		v := &verifier{}
		result := v.verifyRevocation(context.Background(), gradedRevocationOutcome(chain, level))
		if result.Action != trustpolicy.ActionLog {
			t.Fatalf("result action = %q, want %q", result.Action, trustpolicy.ActionLog)
		}
	})

	t.Run("graded override", func(t *testing.T) {
		level := gradedLevel(map[trustpolicy.ValidationType]trustpolicy.ValidationAction{
			trustpolicy.TypeRevocation:            trustpolicy.ActionLog,
			trustpolicy.TypeRevocationUnavailable: trustpolicy.ActionEnforce,
		})
		v := &verifier{}
		result := v.verifyRevocation(context.Background(), gradedRevocationOutcome(chain, level))
		if result.Action != trustpolicy.ActionEnforce {
			t.Fatalf("result action = %q, want %q", result.Action, trustpolicy.ActionEnforce)
		}
		if !isCriticalFailure(result) {
			t.Fatal("expected the undetermined status to be a critical failure")
		}
	})
}

// TestVerifyRevocationGradedLevelFromPolicy exercises the end-to-end path from
// a JSON trust policy override to the action applied by verifyRevocation,
// proving that configuration is read through the existing contract.
func TestVerifyRevocationGradedLevelFromPolicy(t *testing.T) {
	chain := gradedRevocationChain()
	sigVerification := trustpolicy.SignatureVerification{
		VerificationLevel: "strict",
		Override: map[trustpolicy.ValidationType]trustpolicy.ValidationAction{
			trustpolicy.TypeRevoked:               trustpolicy.ActionLog,
			trustpolicy.TypeRevocationUnavailable: trustpolicy.ActionEnforce,
		},
	}
	level, err := sigVerification.GetVerificationLevel()
	if err != nil {
		t.Fatalf("GetVerificationLevel failed: %v", err)
	}

	t.Run("revoked is logged", func(t *testing.T) {
		v := &verifier{revocationCodeSigningValidator: &scriptedRevocationValidator{result: revocationresult.ResultRevoked}}
		result := v.verifyRevocation(context.Background(), gradedRevocationOutcome(chain, level))
		if result.Action != trustpolicy.ActionLog {
			t.Fatalf("result action = %q, want %q", result.Action, trustpolicy.ActionLog)
		}
		if isCriticalFailure(result) {
			t.Fatal("a logged revocation must not be a critical failure")
		}
	})

	t.Run("undetermined is enforced", func(t *testing.T) {
		v := &verifier{revocationCodeSigningValidator: &scriptedRevocationValidator{result: revocationresult.ResultUnknown}}
		result := v.verifyRevocation(context.Background(), gradedRevocationOutcome(chain, level))
		if result.Action != trustpolicy.ActionEnforce {
			t.Fatalf("result action = %q, want %q", result.Action, trustpolicy.ActionEnforce)
		}
		if !isCriticalFailure(result) {
			t.Fatal("an enforced undetermined status must be a critical failure")
		}
	})
}

// TestVerifyRevocationSkipDoesNotReportGradedOutcome guards the boundary that
// graded actions never turn into a revocation check: when the umbrella action
// is "skip" the verifier must not perform the check, regardless of any graded
// override.
func TestVerifyRevocationSkipDoesNotReportGradedOutcome(t *testing.T) {
	level := gradedLevel(map[trustpolicy.ValidationType]trustpolicy.ValidationAction{
		trustpolicy.TypeRevocation:            trustpolicy.ActionSkip,
		trustpolicy.TypeRevocationUnavailable: trustpolicy.ActionEnforce,
		trustpolicy.TypeRevoked:               trustpolicy.ActionEnforce,
	})
	if shouldVerifyRevocation(level, nil) {
		t.Fatal("expected a skipped revocation check not to be performed")
	}

	// A graded-only configuration keeps the base umbrella action, so the
	// check is still performed.
	gradedOnly := gradedLevel(map[trustpolicy.ValidationType]trustpolicy.ValidationAction{
		trustpolicy.TypeRevocationUnavailable: trustpolicy.ActionLog,
	})
	if !shouldVerifyRevocation(gradedOnly, nil) {
		t.Fatal("graded actions alone must not disable the revocation check")
	}

	// A plugin taking over the check still bypasses notation's own check.
	if shouldVerifyRevocation(gradedLevel(map[trustpolicy.ValidationType]trustpolicy.ValidationAction{
		trustpolicy.TypeRevocation: trustpolicy.ActionEnforce,
	}), []pluginframework.Capability{pluginframework.CapabilityRevocationCheckVerifier}) {
		t.Fatal("expected the revocation check to be bypassed when a plugin handles it")
	}
}

// TestRevocationFinalResultMalformedResults pins the boundary behavior when a
// caller-supplied validator returns a result slice that does not line up with
// the certificate chain: the status must be treated as unknown (never OK), so
// the failure path stays closed instead of panicking or silently passing.
func TestRevocationFinalResultMalformedResults(t *testing.T) {
	chain := gradedRevocationChain()

	ok := func() *revocationresult.CertRevocationResult {
		return &revocationresult.CertRevocationResult{
			Result:           revocationresult.ResultOK,
			RevocationMethod: revocationresult.RevocationMethodOCSP,
		}
	}

	t.Run("short result slice", func(t *testing.T) {
		results := []*revocationresult.CertRevocationResult{ok(), ok()}
		finalResult, subject := revocationFinalResult(results, chain, log.Discard)
		if finalResult != revocationresult.ResultUnknown {
			t.Fatalf("final result = %v, want %v", finalResult, revocationresult.ResultUnknown)
		}
		if subject != chain[0].Subject.String() {
			t.Fatalf("subject = %q, want leaf subject %q", subject, chain[0].Subject.String())
		}
	})

	t.Run("long result slice", func(t *testing.T) {
		results := []*revocationresult.CertRevocationResult{ok(), ok(), ok(), ok()}
		finalResult, _ := revocationFinalResult(results, chain, log.Discard)
		if finalResult != revocationresult.ResultUnknown {
			t.Fatalf("final result = %v, want %v", finalResult, revocationresult.ResultUnknown)
		}
	})

	t.Run("nil entry", func(t *testing.T) {
		results := []*revocationresult.CertRevocationResult{ok(), ok(), nil}
		finalResult, _ := revocationFinalResult(results, chain, log.Discard)
		if finalResult != revocationresult.ResultUnknown {
			t.Fatalf("final result = %v, want %v", finalResult, revocationresult.ResultUnknown)
		}
	})

	t.Run("well formed all ok", func(t *testing.T) {
		results := []*revocationresult.CertRevocationResult{ok(), ok(), ok()}
		finalResult, subject := revocationFinalResult(results, chain, log.Discard)
		if finalResult != revocationresult.ResultOK || subject != "" {
			t.Fatalf("final result = %v, subject = %q, want OK and empty subject", finalResult, subject)
		}
	})
}

var _ revocation.Validator = (*scriptedRevocationValidator)(nil)
