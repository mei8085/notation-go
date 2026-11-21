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
	"net/http"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ocsp"

	"github.com/notaryproject/notation-core-go/revocation"
	"github.com/notaryproject/notation-core-go/revocation/purpose"
	revocationresult "github.com/notaryproject/notation-core-go/revocation/result"
	"github.com/notaryproject/notation-core-go/signature"
	"github.com/notaryproject/notation-core-go/signature/jws"
	"github.com/notaryproject/notation-core-go/testhelper"
	"github.com/notaryproject/notation-go"
	"github.com/notaryproject/notation-go/dir"
	"github.com/notaryproject/notation-go/verifier/trustpolicy"
	"github.com/notaryproject/notation-go/verifier/truststore"
	"github.com/notaryproject/tspclient-go"
)

// mockRevocationValidator is a test-only implementation of
// revocation.Validator. It records the AuthenticSigningTime passed to the
// revocation check and returns a per-cert result built from the configured
// result.
type mockRevocationValidator struct {
	mu sync.Mutex

	// result is the revocation result returned for every non-root
	// certificate; the root certificate is always reported as
	// NonRevokable, mirroring the real validator.
	result revocationresult.Result

	// err is returned by ValidateContext when non-nil.
	err error

	// capturedSigningTime is the AuthenticSigningTime received in the
	// last ValidateContext call.
	capturedSigningTime time.Time

	// callCount counts ValidateContext invocations.
	callCount int
}

func (m *mockRevocationValidator) ValidateContext(_ context.Context, opts revocation.ValidateContextOptions) ([]*revocationresult.CertRevocationResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.callCount++
	m.capturedSigningTime = opts.AuthenticSigningTime
	if m.err != nil {
		return nil, m.err
	}
	certResults := make([]*revocationresult.CertRevocationResult, len(opts.CertChain))
	for i := range opts.CertChain {
		if i == len(opts.CertChain)-1 {
			// root certificate is never checked by OCSP or CRL
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
			Result: m.result,
			ServerResults: []*revocationresult.ServerResult{{
				Result:           m.result,
				Server:           "mock://revocation",
				RevocationMethod: revocationresult.RevocationMethodOCSP,
			}},
			RevocationMethod: revocationresult.RevocationMethodOCSP,
		}
	}
	return certResults, nil
}

func (m *mockRevocationValidator) lastSigningTime() time.Time {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.capturedSigningTime
}

// createX509MockOutcome builds a VerificationOutcome under signing scheme
// notary.x509 for revocation unit tests.
func createX509MockOutcome(certChain []*x509.Certificate) *notation.VerificationOutcome {
	return &notation.VerificationOutcome{
		EnvelopeContent: &signature.EnvelopeContent{
			SignerInfo: signature.SignerInfo{
				SignedAttributes: signature.SignedAttributes{
					SigningScheme: signature.SigningSchemeX509,
				},
				CertificateChain: certChain,
			},
		},
		VerificationLevel: &trustpolicy.VerificationLevel{
			Enforcement: map[trustpolicy.ValidationType]trustpolicy.ValidationAction{
				trustpolicy.TypeRevocation: trustpolicy.ActionEnforce,
			},
		},
	}
}

// newRevocationTestVerifier builds a verifier with a mock code signing
// revocation validator.
func newRevocationTestVerifier(m revocation.Validator) *verifier {
	return &verifier{
		revocationCodeSigningValidator: m,
	}
}

func TestVerifyRevocationWithTrustedTimestamp(t *testing.T) {
	revokableTuples := testhelperRevokableChain(t)
	revokableChain := []*x509.Certificate{revokableTuples[0].Cert, revokableTuples[1].Cert, revokableTuples[2].Cert}
	trustedTimestampTime := time.Date(2024, time.January, 1, 12, 0, 0, 0, time.UTC)

	t.Run("notary.x509 with trusted timestamp passes timestamp time to revocation check", func(t *testing.T) {
		mockValidator := &mockRevocationValidator{result: revocationresult.ResultOK}
		v := newRevocationTestVerifier(mockValidator)
		authenticTimestamp := &tspclient.Timestamp{Value: trustedTimestampTime}
		outcome := createX509MockOutcome(revokableChain)

		result := v.verifyRevocation(context.Background(), authenticTimestamp, outcome)
		if result.Error != nil {
			t.Fatalf("expected revocation to succeed, but got %v", result.Error)
		}
		if !mockValidator.lastSigningTime().Equal(trustedTimestampTime) {
			t.Fatalf("expected revocation check to use trusted timestamp time %v, but got %v", trustedTimestampTime, mockValidator.lastSigningTime())
		}
		if mockValidator.callCount != 1 {
			t.Fatalf("expected exactly one revocation check, but got %d", mockValidator.callCount)
		}
	})

	t.Run("notary.x509 without trusted timestamp falls back to zero time (current time semantics)", func(t *testing.T) {
		mockValidator := &mockRevocationValidator{result: revocationresult.ResultOK}
		v := newRevocationTestVerifier(mockValidator)
		outcome := createX509MockOutcome(revokableChain)

		result := v.verifyRevocation(context.Background(), nil, outcome)
		if result.Error != nil {
			t.Fatalf("expected revocation to succeed, but got %v", result.Error)
		}
		if !mockValidator.lastSigningTime().IsZero() {
			t.Fatalf("expected zero AuthenticSigningTime when no trusted timestamp exists, but got %v", mockValidator.lastSigningTime())
		}
	})

	t.Run("notary.x509 signing time attribute is ignored without trusted timestamp", func(t *testing.T) {
		mockValidator := &mockRevocationValidator{result: revocationresult.ResultOK}
		v := newRevocationTestVerifier(mockValidator)
		outcome := createX509MockOutcome(revokableChain)
		// the unauthenticated signing time attribute must never be used as
		// revocation evidence under notary.x509
		outcome.EnvelopeContent.SignerInfo.SignedAttributes.SigningTime = time.Date(2030, time.January, 1, 0, 0, 0, 0, time.UTC)

		result := v.verifyRevocation(context.Background(), nil, outcome)
		if result.Error != nil {
			t.Fatalf("expected revocation to succeed, but got %v", result.Error)
		}
		if !mockValidator.lastSigningTime().IsZero() {
			t.Fatalf("expected unauthenticated signing time to be ignored, but got %v", mockValidator.lastSigningTime())
		}
	})

	t.Run("notary.x509.signingAuthority uses signed authentic signing time, not timestamp", func(t *testing.T) {
		mockValidator := &mockRevocationValidator{result: revocationresult.ResultOK}
		v := newRevocationTestVerifier(mockValidator)
		// even if a timestamp is passed, the signingAuthority scheme must use
		// the signed authentic signing time and ignore it
		authenticTimestamp := &tspclient.Timestamp{Value: trustedTimestampTime}
		authenticSigningTime := time.Date(2023, time.June, 15, 9, 30, 0, 0, time.UTC)
		outcome := createMockOutcome(revokableChain, authenticSigningTime)

		result := v.verifyRevocation(context.Background(), authenticTimestamp, outcome)
		if result.Error != nil {
			t.Fatalf("expected revocation to succeed, but got %v", result.Error)
		}
		if !mockValidator.lastSigningTime().Equal(authenticSigningTime) {
			t.Fatalf("expected signed authentic signing time %v, but got %v", authenticSigningTime, mockValidator.lastSigningTime())
		}
	})
}

func TestVerifyRevocationTimestampBeforeAndAfterRevocation(t *testing.T) {
	revokableTuples := testhelperRevokableChain(t)
	revokableChain := []*x509.Certificate{revokableTuples[0].Cert, revokableTuples[1].Cert, revokableTuples[2].Cert}
	// invalidity date: the certificate became invalid at this point in time.
	invalidityDate := time.Date(2024, time.June, 1, 0, 0, 0, 0, time.UTC)
	beforeRevocation := invalidityDate.Add(-24 * time.Hour) // signature produced before the key compromise
	afterRevocation := invalidityDate.Add(24 * time.Hour)   // signature produced after the key compromise

	t.Run("signature produced before revocation with invalidity date is explainable and not revoked at signing time", func(t *testing.T) {
		// the mock models the OCSP/CRL InvalidityDate semantics already
		// implemented in notation-core-go: when AuthenticSigningTime is
		// before the invalidity date, the certificate is treated as not
		// revoked at the signing time. Here we assert the verifier supplies
		// the trusted timestamp time so that decision can be made and is
		// stable.
		mockValidator := &mockRevocationValidator{result: revocationresult.ResultOK}
		v := newRevocationTestVerifier(mockValidator)
		authenticTimestamp := &tspclient.Timestamp{Value: beforeRevocation}
		outcome := createX509MockOutcome(revokableChain)

		result := v.verifyRevocation(context.Background(), authenticTimestamp, outcome)
		if result.Error != nil {
			t.Fatalf("expected signature made before revocation to remain valid based on the trusted timestamp, but got %v", result.Error)
		}
		if !mockValidator.lastSigningTime().Equal(beforeRevocation) {
			t.Fatalf("expected signing-before-revocation time %v to be passed, but got %v", beforeRevocation, mockValidator.lastSigningTime())
		}
	})

	t.Run("signature produced after revocation stays revoked and explainable", func(t *testing.T) {
		mockValidator := &mockRevocationValidator{result: revocationresult.ResultRevoked}
		v := newRevocationTestVerifier(mockValidator)
		authenticTimestamp := &tspclient.Timestamp{Value: afterRevocation}
		outcome := createX509MockOutcome(revokableChain)

		result := v.verifyRevocation(context.Background(), authenticTimestamp, outcome)
		if result.Error == nil {
			t.Fatal("expected revocation to fail for a signature produced after the certificate was revoked")
		}
		expectedErrMsg := fmt.Sprintf("signing certificate with subject %q is revoked", revokableChain[0].Subject.String())
		if result.Error.Error() != expectedErrMsg {
			t.Fatalf("expected error %q, but got %q", expectedErrMsg, result.Error.Error())
		}
		if !mockValidator.lastSigningTime().Equal(afterRevocation) {
			t.Fatalf("expected signing-after-revocation time %v to be passed, but got %v", afterRevocation, mockValidator.lastSigningTime())
		}
	})

	t.Run("missing timestamp cannot replace current revocation conclusion: revoked stays revoked", func(t *testing.T) {
		mockValidator := &mockRevocationValidator{result: revocationresult.ResultRevoked}
		v := newRevocationTestVerifier(mockValidator)
		// nil timestamp: timestamp evidence is absent
		outcome := createX509MockOutcome(revokableChain)

		result := v.verifyRevocation(context.Background(), nil, outcome)
		if result.Error == nil {
			t.Fatal("expected revoked certificate to remain revoked when timestamp evidence is missing")
		}
		if !mockValidator.lastSigningTime().IsZero() {
			t.Fatalf("expected zero signing time without trusted timestamp, but got %v", mockValidator.lastSigningTime())
		}
	})

	t.Run("untrusted or invalid timestamp cannot replace current revocation conclusion", func(t *testing.T) {
		// an invalid timestamp is represented by passing nil; the verifier
		// must behave exactly as in the missing-timestamp case.
		mockValidator := &mockRevocationValidator{result: revocationresult.ResultRevoked}
		v := newRevocationTestVerifier(mockValidator)
		outcome := createX509MockOutcome(revokableChain)
		outcome.EnvelopeContent.SignerInfo.UnsignedAttributes.TimestampSignature = []byte("not-a-valid-timestamp-token")

		result := v.verifyRevocation(context.Background(), nil, outcome)
		if result.Error == nil {
			t.Fatal("expected revoked certificate to remain revoked when timestamp content is invalid")
		}
		if !mockValidator.lastSigningTime().IsZero() {
			t.Fatalf("expected zero signing time when timestamp is invalid, but got %v", mockValidator.lastSigningTime())
		}
	})

	t.Run("unknown revocation status remains unknown and explainable", func(t *testing.T) {
		mockValidator := &mockRevocationValidator{result: revocationresult.ResultUnknown}
		v := newRevocationTestVerifier(mockValidator)
		authenticTimestamp := &tspclient.Timestamp{Value: beforeRevocation}
		outcome := createX509MockOutcome(revokableChain)

		result := v.verifyRevocation(context.Background(), authenticTimestamp, outcome)
		if result.Error == nil {
			t.Fatal("expected unknown revocation status to be reported as an error")
		}
		expectedErrMsg := fmt.Sprintf("signing certificate with subject %q revocation status is unknown", revokableChain[0].Subject.String())
		if result.Error.Error() != expectedErrMsg {
			t.Fatalf("expected error %q, but got %q", expectedErrMsg, result.Error.Error())
		}
	})

	t.Run("revocation validator error is reported as unable to check", func(t *testing.T) {
		mockValidator := &mockRevocationValidator{err: errors.New("network unavailable")}
		v := newRevocationTestVerifier(mockValidator)
		authenticTimestamp := &tspclient.Timestamp{Value: beforeRevocation}
		outcome := createX509MockOutcome(revokableChain)

		result := v.verifyRevocation(context.Background(), authenticTimestamp, outcome)
		if result.Error == nil {
			t.Fatal("expected an error when the revocation validator fails")
		}
		expectedErrMsg := "unable to check revocation status, err: network unavailable"
		if result.Error.Error() != expectedErrMsg {
			t.Fatalf("expected error %q, but got %q", expectedErrMsg, result.Error.Error())
		}
	})
}

// TestVerifyRevocationTimestampIsPerSignatureState verifies that the trusted
// timestamp used for revocation is passed per invocation rather than kept as
// verifier state, so a single shared verifier can be used concurrently (and
// across many signatures) without one signature's timestamp leaking into
// another's revocation decision. Run with -race to detect data races.
func TestVerifyRevocationTimestampIsPerSignatureState(t *testing.T) {
	revokableTuples := testhelperRevokableChain(t)
	revokableChain := []*x509.Certificate{revokableTuples[0].Cert, revokableTuples[1].Cert, revokableTuples[2].Cert}
	mockValidator := &mockRevocationValidator{result: revocationresult.ResultOK}
	// one verifier instance shared by every goroutine: it carries no mutable
	// per-signature state.
	sharedVerifier := newRevocationTestVerifier(mockValidator)

	const goroutines = 50
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		i := i
		go func() {
			defer wg.Done()
			outcome := createX509MockOutcome(revokableChain)
			if i%2 == 0 {
				// half the calls provide a trusted timestamp
				ts := &tspclient.Timestamp{Value: time.Date(2024, time.January, 1, 0, 0, i, 0, time.UTC)}
				if result := sharedVerifier.verifyRevocation(context.Background(), ts, outcome); result.Error != nil {
					t.Errorf("expected revocation with timestamp to succeed, got %v", result.Error)
				}
			} else {
				// the other half provide no timestamp evidence
				if result := sharedVerifier.verifyRevocation(context.Background(), nil, outcome); result.Error != nil {
					t.Errorf("expected revocation without timestamp to succeed, got %v", result.Error)
				}
			}
		}()
	}
	wg.Wait()
	if mockValidator.callCount != goroutines {
		t.Fatalf("expected %d revocation checks, but got %d", goroutines, mockValidator.callCount)
	}

	// deterministic, sequential check that each distinct per-call timestamp is
	// what the revocation validator actually receives
	for i := 0; i < 5; i++ {
		want := time.Date(2024, time.January, 1, 0, 0, i, 0, time.UTC)
		outcome := createX509MockOutcome(revokableChain)
		if result := sharedVerifier.verifyRevocation(context.Background(), &tspclient.Timestamp{Value: want}, outcome); result.Error != nil {
			t.Fatalf("expected revocation to succeed, got %v", result.Error)
		}
		if got := mockValidator.lastSigningTime(); !got.Equal(want) {
			t.Fatalf("expected per-call timestamp %v to be used, but got %v", want, got)
		}
	}
}

func TestVerifyAuthenticTimestampReturnsTrustedTimestamp(t *testing.T) {
	dir.UserConfigDir = "testdata"
	trustStore := truststore.NewX509TrustStore(dir.ConfigFS())
	dummyTrustPolicy := &trustpolicy.TrustPolicy{
		Name:           "test-timestamp",
		RegistryScopes: []string{"*"},
		SignatureVerification: trustpolicy.SignatureVerification{
			VerificationLevel: trustpolicy.LevelStrict.Name,
			VerifyTimestamp:   trustpolicy.OptionAlways,
		},
		TrustStores:       []string{"ca:valid-trust-store", "tsa:test-timestamp"},
		TrustedIdentities: []string{"*"},
	}
	revocationTimestampingValidator, err := revocation.NewWithOptions(revocation.Options{
		OCSPHTTPClient:   &http.Client{Timeout: 2 * time.Second},
		CertChainPurpose: purpose.Timestamping,
	})
	if err != nil {
		t.Fatalf("failed to get revocation timestamp client: %v", err)
	}

	t.Run("fully verified timestamp countersignature returns non-nil timestamp", func(t *testing.T) {
		envContent, err := parseEnvContent("testdata/timestamp/sigEnv/jwsWithTimestamp.sig", jws.MediaTypeEnvelope)
		if err != nil {
			t.Fatalf("failed to get signature envelope content: %v", err)
		}
		outcome := &notation.VerificationOutcome{
			EnvelopeContent:   envContent,
			VerificationLevel: trustpolicy.LevelStrict,
		}
		authenticTimestamp, authenticTimestampResult := verifyAuthenticTimestamp(
			context.Background(), dummyTrustPolicy.Name, dummyTrustPolicy.TrustStores,
			dummyTrustPolicy.SignatureVerification, trustStore, revocationTimestampingValidator, outcome)
		if authenticTimestampResult.Error != nil {
			t.Fatalf("expected timestamp verification to succeed, but got %v", authenticTimestampResult.Error)
		}
		if authenticTimestamp == nil {
			t.Fatal("expected a non-nil trusted timestamp after successful verification")
		}
		if authenticTimestamp.Value.IsZero() {
			t.Fatal("expected the trusted timestamp to carry a non-zero time")
		}
	})

	t.Run("missing timestamp countersignature returns nil timestamp and error", func(t *testing.T) {
		envContent, err := parseEnvContent("testdata/timestamp/sigEnv/withoutTimestamp.sig", jws.MediaTypeEnvelope)
		if err != nil {
			t.Fatalf("failed to get signature envelope content: %v", err)
		}
		outcome := &notation.VerificationOutcome{
			EnvelopeContent:   envContent,
			VerificationLevel: trustpolicy.LevelStrict,
		}
		authenticTimestamp, authenticTimestampResult := verifyAuthenticTimestamp(
			context.Background(), dummyTrustPolicy.Name, dummyTrustPolicy.TrustStores,
			dummyTrustPolicy.SignatureVerification, trustStore, revocationTimestampingValidator, outcome)
		if authenticTimestampResult.Error == nil {
			t.Fatal("expected an error when the timestamp countersignature is missing")
		}
		if authenticTimestamp != nil {
			t.Fatalf("expected nil timestamp when evidence is missing, but got %#v", authenticTimestamp)
		}
	})

	t.Run("invalid timestamp content returns nil timestamp and error", func(t *testing.T) {
		envContent, err := parseEnvContent("testdata/timestamp/sigEnv/withoutTimestamp.sig", jws.MediaTypeEnvelope)
		if err != nil {
			t.Fatalf("failed to get signature envelope content: %v", err)
		}
		envContent.SignerInfo.UnsignedAttributes.TimestampSignature = []byte("invalid-token-content")
		outcome := &notation.VerificationOutcome{
			EnvelopeContent:   envContent,
			VerificationLevel: trustpolicy.LevelStrict,
		}
		authenticTimestamp, authenticTimestampResult := verifyAuthenticTimestamp(
			context.Background(), dummyTrustPolicy.Name, dummyTrustPolicy.TrustStores,
			dummyTrustPolicy.SignatureVerification, trustStore, revocationTimestampingValidator, outcome)
		if authenticTimestampResult.Error == nil {
			t.Fatal("expected an error when the timestamp content is invalid")
		}
		if authenticTimestamp != nil {
			t.Fatalf("expected nil timestamp when content is invalid, but got %#v", authenticTimestamp)
		}
	})

	t.Run("timestamp verification disabled returns nil timestamp without error", func(t *testing.T) {
		disabledPolicy := &trustpolicy.TrustPolicy{
			Name:           "test-timestamp-disabled",
			RegistryScopes: []string{"*"},
			SignatureVerification: trustpolicy.SignatureVerification{
				VerificationLevel: trustpolicy.LevelStrict.Name,
				VerifyTimestamp:   trustpolicy.OptionAlways,
			},
			// no tsa trust store configured: timestamp verification disabled
			TrustStores:       []string{"ca:valid-trust-store"},
			TrustedIdentities: []string{"*"},
		}
		envContent, err := parseEnvContent("testdata/timestamp/sigEnv/jwsWithTimestamp.sig", jws.MediaTypeEnvelope)
		if err != nil {
			t.Fatalf("failed to get signature envelope content: %v", err)
		}
		outcome := &notation.VerificationOutcome{
			EnvelopeContent:   envContent,
			VerificationLevel: trustpolicy.LevelStrict,
		}
		authenticTimestamp, authenticTimestampResult := verifyAuthenticTimestamp(
			context.Background(), disabledPolicy.Name, disabledPolicy.TrustStores,
			disabledPolicy.SignatureVerification, trustStore, revocationTimestampingValidator, outcome)
		if authenticTimestampResult.Error != nil {
			t.Fatalf("expected no error when timestamp verification is disabled, but got %v", authenticTimestampResult.Error)
		}
		if authenticTimestamp != nil {
			t.Fatalf("expected nil timestamp when verification is disabled, but got %#v", authenticTimestamp)
		}
	})

	t.Run("signingAuthority scheme never returns a timestamp", func(t *testing.T) {
		envContent, err := parseEnvContent("testdata/timestamp/sigEnv/jwsWithTimestamp.sig", jws.MediaTypeEnvelope)
		if err != nil {
			t.Fatalf("failed to get signature envelope content: %v", err)
		}
		signingTime := time.Date(2024, time.January, 1, 12, 0, 0, 0, time.UTC)
		envContent.SignerInfo.SignedAttributes.SigningScheme = signature.SigningSchemeX509SigningAuthority
		envContent.SignerInfo.SignedAttributes.SigningTime = signingTime
		for _, cert := range envContent.SignerInfo.CertificateChain {
			cert.NotBefore = signingTime.Add(-time.Hour)
			cert.NotAfter = signingTime.Add(time.Hour)
		}
		outcome := &notation.VerificationOutcome{
			EnvelopeContent:   envContent,
			VerificationLevel: trustpolicy.LevelStrict,
		}
		authenticTimestamp, authenticTimestampResult := verifyAuthenticTimestamp(
			context.Background(), dummyTrustPolicy.Name, dummyTrustPolicy.TrustStores,
			dummyTrustPolicy.SignatureVerification, trustStore, revocationTimestampingValidator, outcome)
		if authenticTimestampResult.Error != nil {
			t.Fatalf("expected signingAuthority timestamp check to succeed, but got %v", authenticTimestampResult.Error)
		}
		if authenticTimestamp != nil {
			t.Fatalf("expected nil timestamp under signingAuthority scheme, but got %#v", authenticTimestamp)
		}
	})
}

// TestVerifyRevocationTrustedTimestampInvalidityDate drives the real
// notation-core-go revocation validator against a mock OCSP responder that
// reports the leaf certificate as revoked with an InvalidityDate extension.
// It proves end to end that:
//   - a trusted timestamp before the invalidity date makes the signature
//     explainable as "not revoked at signing time" (OCSP Good after
//     InvalidityDate comparison), and
//   - a trusted timestamp after the invalidity date keeps the signature
//     revoked, and
//   - the absence of trusted timestamp evidence cannot replace the current
//     revocation conclusion (the revoked response stays revoked).
func TestVerifyRevocationTrustedTimestampInvalidityDate(t *testing.T) {
	revokableTuples := testhelper.GetRevokableRSAChain(3)
	revokableChain := []*x509.Certificate{revokableTuples[0].Cert, revokableTuples[1].Cert, revokableTuples[2].Cert}

	invalidityDate := time.Now().Add(-1 * time.Hour)
	beforeInvalidity := invalidityDate.Add(-2 * time.Hour)
	afterInvalidity := invalidityDate.Add(2 * time.Hour)

	// mock OCSP responder: revoked status carrying an InvalidityDate extension
	ocspHTTPClient := testhelper.MockClient(revokableTuples, []ocsp.ResponseStatus{ocsp.Revoked}, &invalidityDate, true)
	validator, err := revocation.NewWithOptions(revocation.Options{
		OCSPHTTPClient:   ocspHTTPClient,
		CertChainPurpose: purpose.CodeSigning,
	})
	if err != nil {
		t.Fatalf("failed to create revocation validator: %v", err)
	}

	t.Run("trusted timestamp before invalidity date: not revoked at signing time", func(t *testing.T) {
		v := &verifier{revocationCodeSigningValidator: validator}
		authenticTimestamp := &tspclient.Timestamp{Value: beforeInvalidity}
		outcome := createX509MockOutcome(revokableChain)

		result := v.verifyRevocation(context.Background(), authenticTimestamp, outcome)
		if result.Error != nil {
			t.Fatalf("expected signature produced before the invalidity date to be treated as not revoked at signing time, but got %v", result.Error)
		}
	})

	t.Run("trusted timestamp after invalidity date: revoked", func(t *testing.T) {
		v := &verifier{revocationCodeSigningValidator: validator}
		authenticTimestamp := &tspclient.Timestamp{Value: afterInvalidity}
		outcome := createX509MockOutcome(revokableChain)

		result := v.verifyRevocation(context.Background(), authenticTimestamp, outcome)
		if result.Error == nil {
			t.Fatal("expected signature produced after the invalidity date to be revoked")
		}
		expectedErrMsg := fmt.Sprintf("signing certificate with subject %q is revoked", revokableChain[0].Subject.String())
		if result.Error.Error() != expectedErrMsg {
			t.Fatalf("expected error %q, but got %q", expectedErrMsg, result.Error.Error())
		}
	})

	t.Run("no trusted timestamp: revoked conclusion based on current time is preserved", func(t *testing.T) {
		v := &verifier{revocationCodeSigningValidator: validator}
		outcome := createX509MockOutcome(revokableChain)

		result := v.verifyRevocation(context.Background(), nil, outcome)
		if result.Error == nil {
			t.Fatal("expected the current-time revocation conclusion to remain revoked without trusted timestamp evidence")
		}
		expectedErrMsg := fmt.Sprintf("signing certificate with subject %q is revoked", revokableChain[0].Subject.String())
		if result.Error.Error() != expectedErrMsg {
			t.Fatalf("expected error %q, but got %q", expectedErrMsg, result.Error.Error())
		}
	})
}

// testhelperRevokableChain returns the shared revokable RSA test chain.
func testhelperRevokableChain(t *testing.T) []testhelper.RSACertTuple {
	t.Helper()
	tuples := testhelper.GetRevokableRSAChain(3)
	zeroTime := time.Time{}
	tuples[0].Cert.NotBefore = zeroTime
	tuples[1].Cert.NotBefore = zeroTime
	tuples[2].Cert.NotBefore = zeroTime
	return tuples
}
