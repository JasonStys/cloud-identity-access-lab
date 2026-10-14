# Test strategy and evidence interpretation

Author: Jason Stys. Critical identity/policy boundaries are verified with real libraries and native executables, not a policy simulator returning canned outcomes.

- Python: actual Ed25519 signatures, algorithm/header/issuer/audience/profile negatives, duplicate keys, inclusive expiry/exclusive MFA, Hypothesis time/verdict properties, revocation/capacity/clock rollback. All cial modules included in95% combined statement/branch gate, no exclusions.
- Native conformance:31 scenarios really verify signed credentials and call installed OPA. The actual-matrix test fails on any unexpected access decision. Mock subprocess cases test only adapter/process/output failure handling and do not count as native acceptance.
- Rego: actual opa fmt/check/test with trusted-registry override negatives for approval, duration, MFA and scope. Policy test coverage is separate from Python coverage.
- Terraform: actual versioned fmt/init(no backend)/validate/native plan-only tests for scoped docs and invalid inputs. No provider mocks disguised as cloud validation, real resources or apply. AWS service-side evaluation remains unverified.
- TypeScript: compiled schema/filter/negative/inert-string tests. Actual browsers: matrix/allow-deny-failed distinction, keyboard/mobile containment, no remote requests/token transport, attachments/downloads, malicious-looking labels and malformed-response rejection, axe WCAG A/AA/help.
- HTTP: actual loopback socket requests for all fixed assets, privacy/Origin/Host/fetch-site guards, unknown/private paths, attachments and no mutation. CLI teardown/no overwrite/link/failed verdict tests.
- Supply chain/docs: full hash-locked Python/integrity-locked npm graph audits, official native-tool digests, redacted full-history Gitleaks, actionlint/ShellCheck, full-SHA actions, exact code maps/file guide/links/privacy/provider-free guards. Security-extended CodeQL covers Python and JS/TS; it is not Rego/HCL SAST.

Case counts and coverage percentages measure specific layers, not complete IAM/MFA/ASVS assurance. Expect-deny tests count as passing only when actual denial occurs. Durations are diagnostic; randomized tokens/OS/process startup make whole report hashes vary between runs, while canonicalizing identical evidence produces identical bytes. The report hash is not a signature.

[Measured validation](reports/validation.md) records source hashes, exact counts, platforms, resolved failures and limitations. Reproduce with README/runbook and all gates after any policy/code change.
