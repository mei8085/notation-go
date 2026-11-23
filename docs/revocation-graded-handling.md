# Graded revocation handling: confirmed revocation vs. undetermined status

This note records the design decision and the review evidence for the graded
handling of revocation results in `notation-go`. It is the "signature basis"
record requested for the final check: it states what is decided, where the
decision lives in code, and how each boundary can be reviewed.

## Problem

Before this change the revocation check collapsed two very different failure
classes into a single `revocation` validation action:

- the certificate chain is **confirmed revoked** (OCSP `revoked`, or the CRL
  lists the certificate), and
- the revocation status **cannot be determined** (OCSP responder or CRL
  distribution point unreachable, OCSP `unknown`, a timeout, or the validator
  itself failing).

An operator who wants to fail closed on a confirmed revocation but only log an
undetermined status (or the other way round) had no way to express that.

## Decision

Two graded override keys refine the existing umbrella `revocation` action.
They are accepted only in `signatureVerification.override` and only take effect
when a revocation check is actually performed.

| override key              | failure class              | accepted actions       |
| ------------------------- | -------------------------- | ---------------------- |
| `revoked`                 | confirmed revocation       | `enforce`, `log`       |
| `revocationUnavailable`   | status could not be found  | `enforce`, `log`       |
| `revocation`              | umbrella / check gating    | `enforce`, `log`, `skip` |

Resolution order, implemented by `VerificationLevel.RevocationAction`:

1. the graded key for the failure class, if configured;
2. otherwise the umbrella `revocation` action;
3. otherwise `enforce` (fail closed, also when the level is `nil`).

The name `revocationUnavailable` follows the ["revocation
unavailable"](https://github.com/notaryproject/specifications/blob/main/specs/trust-store-trust-policy.md#certificate-revocation-evaluation)
wording of the Notary Project specification, which states that a revoked or
undeterminable status fails the step according to the enforced/logged setting.

### Boundaries that are deliberately fixed

- **Graded keys never gate the check.** Only the umbrella `revocation` action
  (or a verification plugin taking over the capability) decides whether the
  check runs. A policy that only sets `revoked`/`revocationUnavailable` keeps
  the base level's umbrella action and therefore still performs the check.
  See `shouldVerifyRevocation`.
- **`skip` is rejected for graded keys.** Skipping the whole check must be
  expressed as `revocation: skip`; a graded `skip` would make the graded rule
  meaningless, so `GetVerificationLevel` rejects it.
- **`revocation: skip` still skips everything.** Graded keys are ignored when
  the check is skipped, because no result exists to grade.
- **A validator failure is undetermined, not revoked.** When the validator
  cannot produce results, the outcome is `revocationUnavailable` so a policy
  that only tolerates undetermined status does not also tolerate a confirmed
  revocation.
- **A malformed validator result is undetermined.** If a caller-supplied
  `revocation.Validator` returns a result slice whose length does not match the
  chain (or a `nil` entry), the status is reported as unknown rather than
  panicking or being treated as OK. See `revocationFinalResult`.
- **Plugin failures are graded as undetermined.** A verification plugin only
  reports success/failure and cannot distinguish the two classes, so a failed
  plugin revocation check is conservatively graded as `revocationUnavailable`.
- **Timestamping certificate chains are always enforced.** Per the
  specification the TSA chain revocation check is always enforced; graded
  actions of the signing chain do not apply to it.

## Compatibility

- Existing `validationActions`, `VerificationLevel` values, validation types
  and the `ValidationResult` shape are unchanged. `revocation` continues to
  behave exactly as before when no graded key is configured.
- Existing error strings are unchanged. Revocation failures additionally carry
  `notation.RevocationStatusError`, whose `Error()` returns the same message,
  so string-comparison callers keep working, while new callers can read
  `Outcome`, `Subject` and `Action`.
- Trust policy documents remain JSON compatible: the graded keys are ordinary
  `override` keys and round-trip through JSON.

## Review anchors

All in `verifier/`:

- `trustpolicy/trustpolicy.go`
  - `TypeRevoked`, `TypeRevocationUnavailable`, `RevocationOutcome`,
    `RevocationGradedTypes`, `RevocationGradedActions`
  - `GetVerificationLevel` (graded key validation and `skip` rejection)
  - `VerificationLevel.RevocationAction` (resolution order)
- `verifier.go`
  - `shouldVerifyRevocation` (gating boundary)
  - `verifyRevocation` (classification and graded actions)
  - `revocationFinalResult` (malformed-result boundary)
  - `verifyTimestamp` (always-enforced TSA chain)
- `errors.go`
  - `RevocationStatusError` (machine-readable basis)
- Tests
  - `trustpolicy/trustpolicy_test.go`: `TestRevocationAction`,
    `TestRevocationOutcomeValues`, `TestGradedRevocationOverrideRoundTrip`,
    graded cases in `TestCustomVerificationLevel`
  - `verifier/revocation_graded_test.go`: `TestVerifyRevocationGradedActions`
    (the main review table), `TestVerifyRevocationValidatorFailureIsUndetermined`,
    `TestVerifyRevocationNilValidatorIsUndetermined`,
    `TestVerifyRevocationGradedLevelFromPolicy`,
    `TestVerifyRevocationSkipDoesNotReportGradedOutcome`,
    `TestRevocationFinalResultMalformedResults`
  - `verifier/verifier_test.go`: graded and policy-update cases in
    `TestVerifyRevocationEnvelope`, graded case in
    `TestVerificationPluginInteractions`

## Policy and state update semantics

Both the verification level and the revocation validator are read at the start
of each `Verify`/`VerifyBlob` call:

- the verification level is re-resolved from the current trust policy statement
  (`GetVerificationLevel`) on every call, so updating the policy document in
  memory and verifying again applies the new graded rules;
- the revocation validator is read from the verifier on every call, so swapping
  the configured validator applies to subsequent checks.

A verifier created from config (`NewOCIVerifierFromConfig` /
`NewBlobVerifierFromConfig`) reads the policy document from disk at construction
time, like before; re-create it to pick up a file edit.

`TestVerifyRevocationEnvelope`'s `policy update applies to subsequent
verification` case pins the in-memory policy update behavior.
