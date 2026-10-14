# Cloud Identity Access Lab

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

Complexity: fixed-size signature/profile verification O(token bytes), bounded revocation expiry reclamation O(revocations), indexed policy registry lookup plus bounded rule checks, matrix O(cases × policy process startup), UI filtering/render O(cases × bounded text). Timing evidence is diagnostic, not a production SLO or fair cross-machine benchmark. The registry and 128-case report limits keep this example finite.

## Safety and scope

No real accounts/data, cloud resources, external authentication/token exchange, MFA enrollment, JWKS network fetch, telemetry, ads or public hosting. HTTP binds only numeric loopback and serves fixed read-only synthetic evidence. This is not a public authorization proxy or compliance certification; trusted HTTPS, real provider configuration, durable/distributed revocation, key rotation, clock discipline and security review are prerequisites to real integration.

Revocation/emergency data are process-local/trusted operator inputs. An attacker controlling the OS, repository, registry, tool lock or executable path is outside the trust boundary. Issuer MFA claims are not proof of real physical challenge completion. See [security disclosure](SECURITY.md).

All workflows avoid Actions artifacts/caches and cloud/id-token privileges. Logs/security results remain distinct storage. State/builds/keys/tokens are ignored, not encrypted. No Actions cleanup or account-permission change is part of this repo.

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
| [cial/engine.py](cial/engine.py) | Jason Stys: trusted fixed-policy OPA adapter, closed request contract and privacy-safe decisions. |
| [cial/evidence.py](cial/evidence.py) | Jason Stys: bounded truthful decision evidence, canonical hashes and inert HTML exports. |
| [cial/identity.py](cial/identity.py) | Jason Stys: pinned Ed25519 JWT verification, authoritative time bounds and in-memory credential revocation. |
| [cial/scenarios.py](cial/scenarios.py) | Jason Stys: real signed-credential and OPA conformance scenarios; outcomes are observed, not canned success. |
| [cial/server.py](cial/server.py) | Jason Stys: loopback-only immutable synthetic evidence viewer, fixed assets and no credential/input endpoints. |
| [cial/tooling.py](cial/tooling.py) | Jason Stys: verify and install fixed official native tools; never execute arbitrary caller-selected programs. |
| [docs/architecture.md](docs/architecture.md) | ADR-001: signed local identity integration and native policy assurance without cloud changes. |
| [docs/contracts.md](docs/contracts.md) | Identity, policy, evidence and infrastructure contracts. |
| [docs/reports/ci.json](docs/reports/ci.json) | Immutable accepted-source Actions check snapshot, not a future guarantee. |
| [docs/reports/validation.md](docs/reports/validation.md) | Validation and acceptance record. |
| [docs/research.md](docs/research.md) | Primary sources and design implications. |
| [docs/runbook.md](docs/runbook.md) | Local setup, evidence, troubleshooting and safe teardown. |
| [docs/security.md](docs/security.md) | Threat model and review boundaries. |
| [docs/testing.md](docs/testing.md) | Test strategy and evidence interpretation. |
| [infra/main.tf](infra/main.tf) | Provider-free validated AWS trust, scoped identity and boundary document generator. |
| [infra/tests/policies.tftest.hcl](infra/tests/policies.tftest.hcl) | Native plan-only Terraform trust/scope/invalid-input tests, no providers. |
| [package-lock.json](package-lock.json) | Complete integrity-locked npm tool graph. |
| [package.json](package.json) | Exact browser tool graph and build/verification commands. |
| [playwright.config.mjs](playwright.config.mjs) | Jason Stys: real local evidence viewer across three browser engines and mobile, with no artifact/cache uploads. |
| [policy/access.rego](policy/access.rego) | Jason Stys: authoritative tenant/action/MFA and time-limited emergency grants in real Rego. |
| [policy/access\_test.rego](policy/access_test.rego) | Jason Stys: native Rego positive/negative and trusted-registry emergency boundary tests. |
| [policy/registry.json](policy/registry.json) | Authoritative synthetic principal/resource/emergency registry; no real identities. |
| [pyproject.toml](pyproject.toml) | Strict Python evidence/conformance lint/type/95% combined coverage gates. |
| [requirements-dev.in](requirements-dev.in) | Exact Python runtime/development dependency inputs. |
| [requirements-dev.lock](requirements-dev.lock) | Complete portable hash-locked Python runtime/development graph. |
| [scripts/build.mjs](scripts/build.mjs) | Jason Stys: copy only reviewed static assets after strict TypeScript compilation. |
| [scripts/code\_map.py](scripts/code_map.py) | Jason Stys: generate exact definition/variable line maps and verify Python function/class contracts. |
| [scripts/file\_guide.py](scripts/file_guide.py) | Jason Stys: exact tracked-file README purpose inventory; unknown files fail instead of receiving guessed descriptions. |
| [scripts/scanners.py](scripts/scanners.py) | Install only hash-pinned official Linux scanner binaries. Created by Jason Stys. |
| [scripts/ts-map.mjs](scripts/ts-map.mjs) | Jason Stys: exact AST declaration/parameter maps for TypeScript/JavaScript and static HTML/CSS control maps. |
| [scripts/validate.sh](scripts/validate.sh) | Jason Stys: real signed-identity/native-policy acceptance and full maintained source/doc checks. |
| [scripts/validate\_repo.py](scripts/validate_repo.py) | Jason Stys: repository privacy/action pins, provider-free infrastructure, exact documentation and native-tool limits. |
| [tests/e2e/viewer.spec.mjs](tests/e2e/viewer.spec.mjs) | Jason Stys: actual native-generated evidence browser filters, downloads, literal rendering and accessible scope. |
| [tests/test\_engine.py](tests/test_engine.py) | Jason Stys: real native OPA conformance plus isolated adapter-shape/time-out failure checks. |
| [tests/test\_evidence.py](tests/test_evidence.py) | Jason Stys: truthful report/property negatives and inert escaping, independent from native policy acceptance. |
| [tests/test\_identity.py](tests/test_identity.py) | Jason Stys: real signature/token-profile negatives, time properties and revocation boundaries. |
| [tests/test\_local.py](tests/test_local.py) | Jason Stys: actual loopback evidence routes, privacy guards, CLI lifecycle and report nonoverwrite. |
| [tests/test\_tooling.py](tests/test_tooling.py) | Jason Stys: isolated official-tool download/hash/extraction negative tests; never execute downloaded test bytes. |
| [tests/ui/model.test.mjs](tests/ui/model.test.mjs) | Jason Stys: native compiled-TypeScript evidence/negative/filter contracts, not policy-engine simulation. |
| [tools.lock.json](tools.lock.json) | Official native-tool/scanner versions, release URLs and SHA256 digests. |
| [tsconfig.json](tsconfig.json) | Strict browser compilation with unchecked-index/nullable safeguards. |
| [web/app.ts](web/app.ts) | Jason Stys: accessible immutable evidence viewer; no token entry, account data, remote APIs or cloud mutation. |
| [web/index.html](web/index.html) | Jason Stys: semantic local-only synthetic identity/access assurance viewer and help. |
| [web/model.ts](web/model.ts) | Jason Stys: runtime-checked bounded evidence contracts, filtering and truthful observed-versus-expected summaries. |
| [web/style.css](web/style.css) | Jason Stys: restrained navy/cyan evidence-console layout with visible focus and mobile-contained tables. |

<!-- END FILE GUIDE -->
