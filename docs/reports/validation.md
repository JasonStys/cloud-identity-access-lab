# Validation and acceptance record

Created by Jason Stys. Recorded 2026-10-14. Accepted source: 3886e1e5bb7fa0594f8804243263d30d37dd70db. All 10 jobs completed successfully: [Validate](https://github.com/JasonStys/cloud-identity-access-lab/actions/runs/38540610192), [CodeQL](https://github.com/JasonStys/cloud-identity-access-lab/actions/runs/38540609834). [Immutable CI snapshot](ci.json) records source SHA, exact job times and URLs. Later documentation/declaration-map maintenance commits rerun both workflows; this record is not a self-referential future-commit guarantee.

## Measured acceptance

| Layer | Observed result | Scope/platform |
| --- | --- | --- |
| Python | 72/72 tests passed on each of four lanes | Python 3.12 Ubuntu; Python 3.14 Ubuntu, Windows and macOS15 Intel; actual native OPA included |
| Python combined statement/branch coverage | 99.20% on all four lanes | All eight cial modules, no omissions; required gate 95%. Does not measure TypeScript/Rego/HCL coverage |
| Native identity/policy matrix | 31/31 scenarios passed | Genuine Ed25519 signatures, strict token/time profile and actual OPA decisions; no mocked fallback |
| Native Rego | 20/20 tests passed | OPA 1.21.2 strict check/format/test on Linux and Windows; separate local Rego line-coverage observation 97.30% after declaration-map refinement |
| Native Terraform | 6/6 tests passed | Terraform 1.16.5 fmt/init(no backend)/validate/plan-only tests, Linux and Windows; no providers/resources/AWS API |
| Native compiled TypeScript | 23/23 checks passed | Exact evidence schema negatives, filtering/verdict distinction and inert string contracts |
| Browser | 16/16 passed | Chromium, Firefox, WebKit and Pixel7 layout; real native-generated matrix, filtering, downloads, malformed/hostile-looking data, no remote traffic, keyboard/overflow/axe WCAG A/AA/help; no retries/skips |
| Static/repository | Passed | Ruff lint/format, strict mypy/TypeScript, Prettier, exact declaration maps, full file inventory, links/privacy/pins/provider-free guard |
| Dependency/secrets/CI hygiene | Passed | Complete hash-locked Python and integrity-locked npm graph audits; no known vulnerabilities, redacted full-history Gitleaks found no secret leaks; actionlint/ShellCheck/full-SHA actions; no advisory exclusions |
| CodeQL security-extended | Two jobs passed; zero open alerts at acceptance | Python and JavaScript/TypeScript; no claim of Rego/HCL CodeQL analysis |

Native/data test counts include positive and expected-denial cases. Duplicated platform executions are not new independent security controls. The matrix's expected result is compared with the actual observed result; denial is not automatically treated as a failed test.

## Local corroboration and verification limits

Windows PC: Python 3.14.6, Node 24.18.1, OPA 1.21.2, Terraform 1.16.5. The accepted runtime source passed72 tests at 99.20% combined coverage,31 actual credential/policy scenarios,20 native Rego tests,6 native Terraform tests,23 TypeScript checks and16 browser checks. In-app browser verified revoked access is denied yet a passing regression, and the help accurately distinguishes local synthetic evidence from real-provider/cloud authentication. JSON/HTML exports contain no tokens or keys. Jason Stys attribution/contact links are present.

CI selected Node 24.21.0 and exact OPA/Terraform tools from reviewed official SHA256 pins. Runtime JWT libraries: PyJWT 2.15.1/cryptography 50.0.2; complete runtime/development dependency graph in requirements-dev.lock. This cryptography release has no macOS Intel wheel; the verified macOS lane built its pinned source distribution. Local macOS Intel installation may require upstream Rust/C/OpenSSL build prerequisites, not merely Python. No claim of tested ARM support or one-click production installation.

Windows command sandbox caused the hash-verified Go OPA binary to fail startup with DLL relocation, while trusted execution outside that command sandbox ran successfully. Local native/Firefox checks used that scoped execution method; no OS/browser/TLS protection, antivirus setting or Docker state was changed. GitHub's fresh native lanes independently passed.

## Findings and corrections retained in history

- Python typing found a generic-server port reference and an Any verdict return. Explicit HTTPServer typing and boolean verdict return retain the actual boundary semantics; strict gates now pass.
- Browser selectors exposed a nested dropdown label whose text included option content. Both filters now use separate explicit labels. All four browser profiles verify actual selection/search, not a relaxed selector or retry.
- CodeQL found a request-derived export filename in Content-Disposition despite route allowlisting. Header filenames now use fixed literals, eliminating tainted request text; finding resolved through source correction, with no suppression/dismissal/exclusion. [Initial analysis](https://github.com/JasonStys/cloud-identity-access-lab/actions/runs/38540312365).
- The first Validate run was canceled by the newer corrective push under normal concurrency control, not erased: [initial run](https://github.com/JasonStys/cloud-identity-access-lab/actions/runs/38540312355). All gates were rerun on the accepted source.
- Native installer verification compares OPA to its official raw binary hash and Terraform to its retained official hash-pinned archive, not a caller-editable receipt. Tampered binaries/archives, wrong sources, links, unsupported hosts and size limits have isolated negative tests.
- Native declaration maps distinguish top-level rules from local bindings and list rule parameters; source-map comments are checked mechanically and native formatting/compilation remains independent.

## Storage and privacy

Initial read-only check 2026-10-14T08:34:31Z:72 repositories, 8,419,929 live artifact bytes, zero private-repository artifact bytes; separate caches 9,029,833,071 bytes. Fresh billing Actions meter showed 0.5 GB used /0.5GB included (100%). Accumulated included billing usage, current live artifacts and separate caches are not equivalent; the quota API did not provide a percentage.

The new repository was verified at zero Actions artifacts and zero active caches. No artifact/cache action, cloud credential action, id-token privilege or CodeQL database upload is configured. Logs/security results remain distinct storage. No deletion, archive/cleanup, budget or retention change was made; fresh approval is required for cleanup.

Working conformance exports, browser reports, tool archives/binaries and environments stay ignored/private locally under out/.tools/.venv/dist. Signing keys/token values remain in process memory, never evidence exports or committed source. The committed snapshot contains only public synthetic labels and CI metadata, not provider credentials or private user data. Ignore is not encryption.

## Interpretation

These results prove bounded local signed-credential/policy integration and provider-free IAM document construction, not live AWS/Azure/GitHub identity authentication, managed-identity enrollment, real MFA challenge completion, IAM Simulator parity or a public authorization proxy. MFA is a verified issuer assertion; synthetic issuers do not authenticate real people. Revocation and emergency grants are trusted process-local state, not distributed durable enforcement.

Trusted real provider configuration/key lifecycle, strong MFA enrollment, clock discipline, durable revocation, actual resource/cloud-policy enforcement, HTTPS and a deployment threat review remain prerequisites for real integration. Test coverage/scans do not prove absence of vulnerabilities or compliance certification. Diagnostic elapsed times are not comparable performance scores/SLOs, and canonical report hashes vary when observed timing changes. Reproduce with README/runbook and rerun every gate after source changes.
