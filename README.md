# Cloud Identity Access Lab

## Native signed-identity application

The Windows portable workbench now provides real selected-registry request evaluation, controlled signature/expiry/revocation/MFA profiles, proposed-entitlement review and the original 31-case assurance suite. Actual Ed25519 verification and pinned native OPA produce every outcome. Prepared scenarios populate ordinary controls in this same application, with no automatic run, real cloud credentials or permission changes.

See the [native user guide](docs/native-workbench.md) and [source/native validation and provenance report](docs/reports/native-workbench-2026-11-10.md). The app includes its runtime, durable private history, literal filtering/details, exact export and readable upstream notices; no separate Python/Node/OPA setup is needed to use the Windows portable. Original source CLI/browser/Terraform interfaces remain available. This is a synthetic engineering lab, not production authentication or a signed installer.


[![Validate](https://github.com/JasonStys/cloud-identity-access-lab/actions/workflows/ci.yml/badge.svg)](https://github.com/JasonStys/cloud-identity-access-lab/actions/workflows/ci.yml) [![CodeQL](https://github.com/JasonStys/cloud-identity-access-lab/actions/workflows/codeql.yml/badge.svg)](https://github.com/JasonStys/cloud-identity-access-lab/actions/workflows/codeql.yml)

Created by **Jason Stys** · [GitHub](https://github.com/JasonStys) · [Contact on LinkedIn](https://www.linkedin.com/in/jason-stys-31b30b351/)

Prove which signed identities can—and cannot—cross an access boundary. Python verifies real Ed25519 JWT signatures and strict token profiles; native Open Policy Agent evaluates least-privilege policy. TypeScript presents the observed evidence. Native Terraform tests validate provider-free AWS-shaped IAM trust/identity/boundary documents.

**Owner-local synthetic assurance lab, not a production identity provider or live-cloud deployment.** The local issuer does not authenticate real people, perform MFA challenges or obtain managed cloud credentials. Those integration boundaries and prerequisites are explicit, not hidden behind simulated success.

## Working features

| Feature | Implementation | Evidence |
| --- | --- | --- |
| Signed identity adapter | Fixed EdDSA key/algorithm, issuer/audience, closed claims/header profile, duplicate rejection | Genuine cryptographic positives/negatives, malformed/forged/future/expired credential tests |
| Least privilege | Trusted registry defines subject/tenant/action ceilings; resource scope intersects identity permissions | Actual OPA decisions, cross-tenant and scope/unknown subject negatives |
| MFA assurance | Human writes require a fresh issuer-attested MFA claim | Missing/stale MFA denials; freshness boundary tests; no real enrollment claim |
| Workload identity | Exact immutable GitHub-shaped workload subject and separate workload permission set | Fork/repository/branch changes and unwanted human privileges denied |
| Temporary access/revocation | Maximum 300-second credential lifetime, exclusive expiry, local credential revocation and subject disablement | Native verifier tests, independent peer survives revocation, clock rollback fails closed |
| Emergency privilege | Trusted two-approver, scoped, time-limited emergency grant plus fresh MFA | Exact start/expiry, duplicate/self approval and duration negatives |
| Cloud policy documents | Provider-free HCL generates AWS OIDC trust, scoped release identity and permissions boundary | Native Terraform validate and plan-only tests; no AWS API, IAM Simulator or apply |
| Evidence viewer/exports | Strict JSON contract, searchable allow/deny/regression views, literal DOM rendering, sanitized JSON/inert HTML/SHA256 | Actual browsers, keyboard/mobile/axe, malicious-looking titles, download and malformed-response tests |
| [Entitlement recertification](docs/recertification.md) | Trusted baseline/proposed registries through genuine signatures and native OPA; tenant/action gains, losses and emergency expiry | Closed bounded contexts, exact input/Rego hashes, immutable review reports; no cloud grants or implied approval |

The generic Rego resource model is deliberately separate from AWS IAM semantics. It does not pretend to evaluate every AWS policy type, resource/session-principal exception, SCP/RCP or KMS/organization interaction.

## Quick start

Prerequisites: Python 3.12+, Node 24+, x86-64 Windows/Linux/macOS. Native tools are installed locally from reviewed official releases with SHA256 verification, not onto global PATH.

macOS Intel builds the pinned cryptography source distribution rather than using a prebuilt wheel; see the runbook for Rust/C/OpenSSL build prerequisites. This is a source-first portfolio lab, not a one-click production installer.

    python -m venv .venv
    .venv\Scripts\python -m pip install --require-hashes -r requirements-dev.lock
    .venv\Scripts\python -m cial.tooling opa
    npm ci --ignore-scripts
    npm run build
    .venv\Scripts\python -m cial serve

Open the printed numeric 127.0.0.1 URL. The server runs the real signed-identity/OPA matrix before showing evidence. Search and filters inspect results; they never grant access. Ctrl+C stops the owned server. Linux/macOS: replace .venv\Scripts\python with .venv/bin/python. No cloud account, Docker, secrets, provider plugins, login setup or database is required.

For new nonoverwriting JSON/HTML/hash evidence:

    .venv\Scripts\python -m cial run --out out/new-evidence

The parent directory must exist; the target must be new and nonlinked. Missing tools, native engine failures and mismatched outcomes are failures, never skipped successes. Keys/tokens remain in memory; reports contain only synthetic labels, expected/observed decisions and diagnostic durations.

## Validate/reproduce

Activate the virtual environment, build npm assets, then:

    bash scripts/validate.sh
    python -m cial.tooling terraform
    .tools/opa check --strict policy
    .tools/opa test policy -v
    .tools/terraform -chdir=infra init -backend=false -input=false
    .tools/terraform -chdir=infra validate
    .tools/terraform -chdir=infra test
    npx playwright install chromium firefox webkit
    npm run test:e2e

On Windows native executables have .exe suffixes. Full commands, platform limits and safe cleanup are in the [runbook](docs/runbook.md). Windows command-sandbox restrictions can prevent Go/Firefox startup; the lab does not change OS/browser protections. CI supplies native cross-platform verification.

[Architecture/ADR](docs/architecture.md) · [contracts](docs/contracts.md) · [threat model](docs/security.md) · [test strategy](docs/testing.md) · [research](docs/research.md) · [measured validation](docs/reports/validation.md) · [contributing](CONTRIBUTING.md)

Complexity: fixed-size signature/profile verification O(token bytes), bounded revocation expiry reclamation O(revocations), indexed policy registry lookup plus bounded rule checks, original assurance matrix O(cases × policy process startup), entitlement review O(contexts × signature/policy work) with two bounded native starts, UI filtering/render O(cases × bounded text). Timing evidence is diagnostic, not a production SLO or fair cross-machine benchmark. The registry and 128-case report limits keep this example finite.

## Safety and scope

No real accounts/data, cloud resources, external authentication/token exchange, MFA enrollment, JWKS network fetch, telemetry, ads or public hosting. HTTP binds only numeric loopback and serves fixed read-only synthetic evidence. This is not a public authorization proxy or compliance certification; trusted HTTPS, real provider configuration, durable/distributed revocation, key rotation, clock discipline and security review are prerequisites to real integration.

Revocation/emergency data are process-local/trusted operator inputs. An attacker controlling the OS, repository, registry, tool lock or executable path is outside the trust boundary. Issuer MFA claims are not proof of real physical challenge completion. See [security disclosure](SECURITY.md).

All workflows avoid Actions artifacts/caches and cloud/id-token privileges. Logs/security results remain distinct storage. State/builds/keys/tokens are ignored, not encrypted. No Actions cleanup or account-permission change is part of this repo.

## Native profile storage correction

Version 1.1.1 rejects pre-existing linked/nonregular fixed profile and SQLite
sidecar entries before initialization can write through an alias. Ordinary
recovery files and existing profile schemas remain supported; no data is reset.
See the [confirmed fixture, recovery tests and scope](docs/reports/profile-admission-2026-11-11.md).
Earlier native releases and documentation retain their own dated evidence.

## Complete file guide

Authored Python/TypeScript code includes purpose/function/class descriptions and checked AST exact-line declaration/parameter maps. Rego/HCL/YAML/Bash use checked lexical rule/configuration maps; native compilers/formatters independently validate syntax. Non-commentable JSON/lock/config purposes are documented below.

<!-- BEGIN FILE GUIDE -->

| File | Purpose |
| --- | --- |
| [.gitattributes](.gitattributes) | Consistent LF checkouts across supported operating systems. |
| [.github/workflows/ci.yml](.github/workflows/ci.yml) | Jason Stys: native identity/policy/IaC/browser checks, no cloud privileges, artifacts or Actions caches. |
| [.github/workflows/codeql.yml](.github/workflows/codeql.yml) | Jason Stys: full supported-language security-extended analysis; no CodeQL database artifact upload. |
| [.gitignore](.gitignore) | Exclude local keys/tokens, native tools, environments, builds and working evidence. |
| [CHANGELOG.md](CHANGELOG.md) | Changelog. |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Contributing. |
| [LICENSE](LICENSE) | MIT license for authored code; upstream tools retain their licenses. |
| [README.md](README.md) | Cloud Identity Access Lab. |
| [SECURITY.md](SECURITY.md) | Security disclosure. |
| [cial/\_\_init\_\_.py](cial/__init__.py) | Jason Stys: synthetic identity-to-policy integration; no import-time network, tokens, keys or cloud changes. |
| [cial/\_\_main\_\_.py](cial/__main__.py) | Jason Stys: genuine signed-identity/OPA matrix runner, nonoverwriting reports and owned-loopback preview. |
| [cial/desktop.py](cial/desktop.py) | Native offline workbench: real project inputs, analysis, searchable evidence, history and export. Jason Stys. |
| [cial/desktop\_io.py](cial/desktop_io.py) | Bounded regular descriptor reads and strict finite JSON for owner-local desktop state. Jason Stys. |
| [cial/desktop\_project.py](cial/desktop_project.py) | Actual signed-request, credential-lifecycle and fixed-OPA entitlement workflows for the native app. Jason Stys. |
| [cial/desktop\_state.py](cial/desktop_state.py) | Owner-local desktop profile, bounded durable bundles and non-overwriting export. Jason Stys. |
| [cial/engine.py](cial/engine.py) | Jason Stys: trusted fixed-policy OPA adapter, closed request contract and privacy-safe decisions. |
| [cial/evidence.py](cial/evidence.py) | Jason Stys: bounded truthful decision evidence, canonical hashes and inert HTML exports. |
| [cial/identity.py](cial/identity.py) | Jason Stys: pinned Ed25519 JWT verification, authoritative time bounds and in-memory credential revocation. |
| [cial/inputs.py](cial/inputs.py) | Bounded stable ordinary-file reads and streaming tool hashes for offline identity inputs. Jason Stys. |
| [cial/recertify.py](cial/recertify.py) | Real signed-context/OPA entitlement comparison of trusted synthetic registries. Jason Stys. |
| [cial/scenarios.py](cial/scenarios.py) | Jason Stys: real signed-credential and OPA conformance scenarios; outcomes are observed, not canned success. |
| [cial/server.py](cial/server.py) | Jason Stys: loopback-only immutable synthetic evidence viewer, fixed assets and no credential/input endpoints. |
| [cial/tooling.py](cial/tooling.py) | Jason Stys: verify and install fixed official native tools; never execute arbitrary caller-selected programs. |
| [docs/architecture.md](docs/architecture.md) | ADR-001: signed local identity integration and native policy assurance without cloud changes. |
| [docs/contracts.md](docs/contracts.md) | Identity, policy, evidence and infrastructure contracts. |
| [docs/handbook.md](docs/handbook.md) | Cloud Identity Access Lab handbook. |
| [docs/native-workbench.md](docs/native-workbench.md) | Native signed-identity workbench. |
| [docs/recertification.md](docs/recertification.md) | Trusted synthetic entitlement recertification. |
| [docs/reports/ci.json](docs/reports/ci.json) | Immutable accepted-source Actions check snapshot, not a future guarantee. |
| [docs/reports/documentation-refresh-2026-11-09.md](docs/reports/documentation-refresh-2026-11-09.md) | Documentation refresh — 2026-11-09. |
| [docs/reports/installed-windows-1.1.1-2026-11-11.md](docs/reports/installed-windows-1.1.1-2026-11-11.md) | Installed Windows 1.1.1 validation · 11 November 2026. |
| [docs/reports/native-workbench-2026-11-10.md](docs/reports/native-workbench-2026-11-10.md) | Native identity workbench and bounded batch validation — 2026-11-10. |
| [docs/reports/portfolio-sync-2026-10-22.md](docs/reports/portfolio-sync-2026-10-22.md) | <!-- File: docs/reports/portfolio-sync-2026-10-22.md; Purpose: certificate-bundle security repair and evidence by Jason Stys. -->. |
| [docs/reports/profile-admission-2026-11-11.md](docs/reports/profile-admission-2026-11-11.md) | Fixed profile entry admission — November 11, 2026. |
| [docs/reports/project-guide.docx](docs/reports/project-guide.docx) | Reviewed Word project guide bound to the documented source revision. |
| [docs/reports/publications.json](docs/reports/publications.json) | Exact Office digests, visual review scopes and immutable source baselines. |
| [docs/reports/recertification-2026-11-09.md](docs/reports/recertification-2026-11-09.md) | Entitlement recertification validation — 2026-11-09. |
| [docs/reports/validation.md](docs/reports/validation.md) | Validation and acceptance record. |
| [docs/reports/windows-application-guide-1.1.1.docx](docs/reports/windows-application-guide-1.1.1.docx) | Reviewed current 1.1.1 installed-app guide: actual screenshots, workflow, immutable code and measured limits. |
| [docs/reports/windows-application-guide-1.1.1.json](docs/reports/windows-application-guide-1.1.1.json) | Current Word, screenshot, source and individually reviewed rendered-page hashes. |
| [docs/research.md](docs/research.md) | Primary sources and design implications. |
| [docs/runbook.md](docs/runbook.md) | Local setup, evidence, troubleshooting and safe teardown. |
| [docs/security.md](docs/security.md) | Threat model and review boundaries. |
| [docs/testing.md](docs/testing.md) | Test strategy and evidence interpretation. |
| [examples/desktop/proposed-registry.json](examples/desktop/proposed-registry.json) | Fictional tenant move and publisher removal, evaluated as data without applying grants. |
| [infra/main.tf](infra/main.tf) | Provider-free validated AWS trust, scoped identity and boundary document generator. |
| [infra/tests/policies.tftest.hcl](infra/tests/policies.tftest.hcl) | Native plan-only Terraform trust/scope/invalid-input tests, no providers. |
| [licenses/GO-LICENSE.txt](licenses/GO-LICENSE.txt) | Unmodified official Go1.27.3 runtime BSD license. |
| [licenses/OPA-LICENSE.txt](licenses/OPA-LICENSE.txt) | Unmodified official OPA Apache2 license text at verified1.22.3. |
| [licenses/OPA-THIRD-PARTY.txt](licenses/OPA-THIRD-PARTY.txt) | Actual84linked Go module copyright/license texts from exact-version official mirrors or immutable source commit. |
| [licenses/opa-linked-modules.txt](licenses/opa-linked-modules.txt) | Public module/version/sum inventory extracted from the SHA-bound official Windows OPA binary; no host/build paths. |
| [package-lock.json](package-lock.json) | Complete integrity-locked npm tool graph. |
| [package.json](package.json) | Exact browser tool graph and build/verification commands. |
| [playwright.config.mjs](playwright.config.mjs) | Jason Stys: real local evidence viewer across three browser engines and mobile, with no artifact/cache uploads. |
| [policy/access.rego](policy/access.rego) | Jason Stys: authoritative tenant/action/MFA and time-limited emergency grants in real Rego. |
| [policy/access\_test.rego](policy/access_test.rego) | Jason Stys: native Rego positive/negative and trusted-registry emergency boundary tests. |
| [policy/registry.json](policy/registry.json) | Authoritative synthetic principal/resource/emergency registry; no real identities. |
| [pyproject.toml](pyproject.toml) | Strict Python evidence/conformance lint/type/95% combined coverage gates. |
| [requirements-dev.in](requirements-dev.in) | Exact Python runtime/development dependency inputs. |
| [requirements-dev.lock](requirements-dev.lock) | Complete portable hash-locked Python runtime/development graph. |
| [requirements-native.lock](requirements-native.lock) | Exact hash-locked Windows native build tools; no first-launch downloads. |
| [scripts/build.mjs](scripts/build.mjs) | Jason Stys: copy only reviewed static assets after strict TypeScript compilation. |
| [scripts/build\_native.py](scripts/build_native.py) | Build the complete real offline workbench as one Windows portable executable. Jason Stys. |
| [scripts/code\_map.py](scripts/code_map.py) | Jason Stys: generate exact definition/variable line maps and verify Python function/class contracts. |
| [scripts/file\_guide.py](scripts/file_guide.py) | Jason Stys: exact tracked-file README purpose inventory; unknown files fail instead of receiving guessed descriptions. |
| [scripts/native\_acceptance.py](scripts/native_acceptance.py) | Real frozen widget/core/history/export and honest failure-evidence acceptance. Jason Stys. |
| [scripts/native\_entry.py](scripts/native_entry.py) | Launch the actual bundled offline project workbench; no setup shell commands. Jason Stys. |
| [scripts/scanners.py](scripts/scanners.py) | Install only hash-pinned official Linux scanner binaries. Created by Jason Stys. |
| [scripts/test\_native\_app.py](scripts/test_native_app.py) | Run the real frozen workbench twice with an owned synthetic profile and exact bundle persistence. Jason Stys. |
| [scripts/ts-map.mjs](scripts/ts-map.mjs) | Jason Stys: exact AST declaration/parameter maps for TypeScript/JavaScript and static HTML/CSS control maps. |
| [scripts/validate.sh](scripts/validate.sh) | Jason Stys: real signed-identity/native-policy acceptance and full maintained source/doc checks. |
| [scripts/validate\_repo.py](scripts/validate_repo.py) | Jason Stys: repository privacy/action pins, provider-free infrastructure, exact documentation and native-tool limits. |
| [tests/e2e/viewer.spec.mjs](tests/e2e/viewer.spec.mjs) | Jason Stys: actual native-generated evidence browser filters, downloads, literal rendering and accessible scope. |
| [tests/test\_batch\_engine.py](tests/test_batch_engine.py) | Genuine all-256 single/batch OPA equivalence and independent fail-closed batch controls. Jason Stys. |
| [tests/test\_desktop\_gui.py](tests/test_desktop_gui.py) | Presentation-adapter unit tests with real core/SQLite workers; real widgets are separately frozen-tested. Jason Stys. |
| [tests/test\_desktop\_project.py](tests/test_desktop_project.py) | Real signed-request/native-OPA desktop oracles, registry changes and secret omission. Jason Stys. |
| [tests/test\_desktop\_state.py](tests/test_desktop_state.py) | Independent offline desktop ownership, byte-bound, SQLite and non-overwrite regressions. Jason Stys. |
| [tests/test\_engine.py](tests/test_engine.py) | Jason Stys: real native OPA conformance plus isolated adapter-shape/time-out failure checks. |
| [tests/test\_evidence.py](tests/test_evidence.py) | Jason Stys: truthful report/property negatives and inert escaping, independent from native policy acceptance. |
| [tests/test\_identity.py](tests/test_identity.py) | Jason Stys: real signature/token-profile negatives, time properties and revocation boundaries. |
| [tests/test\_local.py](tests/test_local.py) | Jason Stys: actual loopback evidence routes, privacy guards, CLI lifecycle and report nonoverwrite. |
| [tests/test\_native\_inputs.py](tests/test_native_inputs.py) | Independent real descriptor, child-environment and exact native-resource boundaries. Jason Stys. |
| [tests/test\_profile\_admission.py](tests/test_profile_admission.py) | Actual pre-existing alias refusal and ordinary SQLite recovery continuity. Jason Stys. |
| [tests/test\_publication\_policy.py](tests/test_publication_policy.py) | Jason Stys: independent real-ZIP publication privacy boundary and unknown-file rejection regressions. |
| [tests/test\_recertify.py](tests/test_recertify.py) | Real signed/native-policy recertification and closed trusted-registry boundaries. Jason Stys. |
| [tests/test\_tooling.py](tests/test_tooling.py) | Jason Stys: isolated official-tool download/hash/extraction negative tests; never execute downloaded test bytes. |
| [tests/ui/model.test.mjs](tests/ui/model.test.mjs) | Jason Stys: native compiled-TypeScript evidence/negative/filter contracts, not policy-engine simulation. |
| [tools.lock.json](tools.lock.json) | Official native-tool/scanner versions, release URLs and SHA256 digests. |
| [tsconfig.json](tsconfig.json) | Strict browser compilation with unchecked-index/nullable safeguards. |
| [web/app.ts](web/app.ts) | Jason Stys: accessible immutable evidence viewer; no token entry, account data, remote APIs or cloud mutation. |
| [web/index.html](web/index.html) | Jason Stys: semantic local-only synthetic identity/access assurance viewer and help. |
| [web/model.ts](web/model.ts) | Jason Stys: runtime-checked bounded evidence contracts, filtering and truthful observed-versus-expected summaries. |
| [web/style.css](web/style.css) | Jason Stys: restrained navy/cyan evidence-console layout with visible focus and mobile-contained tables. |

<!-- END FILE GUIDE -->

## Documentation editions

Start with the [organized handbook](docs/handbook.md) for current usage, design, security and test guidance. Reviewed downloadable editions: [project-guide.docx](docs/reports/project-guide.docx).

[Publication identities and source scope](docs/reports/publications.json) · [Documentation validation record](docs/reports/documentation-refresh-2026-11-09.md). Historical results retain their own tested revision and date.

## Current Windows application guide

The published **1.1.1** app has a [four-page illustrated guide](docs/reports/windows-application-guide-1.1.1.docx) with actual installed screenshots, a worked user journey, important source excerpts and practical limits. Read the [installed-app and upgrade results](docs/reports/installed-windows-1.1.1-2026-11-11.md) and [byte/page review manifest](docs/reports/windows-application-guide-1.1.1.json) for exact scope. Earlier Office editions remain historical and unchanged.
