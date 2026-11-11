# Native identity workbench and bounded batch validation — 2026-11-10

Author: Jason Stys. This describes the 1.1.0 source candidate. Publication, installed-PC proof and exact main checks require separate observed acceptance; historical Office/benchmark snapshots retain their dated source scope.

## Implemented workflows

The actual Tk application connects selected closed-schema registries, subjects, requests, explicit clocks, MFA assertions and credential-lifecycle conditions to real Ed25519/PyJWT verification and pinned native OPA. Proposed entitlement review and the original 31-case assurance suite reuse the existing engines. Keys, tokens and raw claims remain in memory; no real identity/cloud account or provider operation is added. Private SQLite history, search/details, exact non-overwriting export, explicit retention, Help/Licenses and normal Exit make the workflows usable without developer commands.

Registry/tool input admission now uses bounded nonblocking one-link ordinary descriptors with identity/stability checks. Actual POSIX FIFO-swap and Windows descriptor negatives protect the new file-input path; the POSIX-only control is explicitly skipped on Windows, not counted as a local pass.

## Genuine failure and performance correction

The initial frozen consumer failed its existing 55-second journey deadline in the original recertification's 256-process loop; the parent then failed its existing 80-second wait while the original 120-second comparison still drained. The first six real request/lifecycle steps had completed. The original automatic temporary cleanup also encountered the still-held synthetic profile lock. These failures are preserved as failures; there is no claim that the OS, DLL loader or runner caused them.

The correction changes actual orchestration: at most 256 contexts are individually signature-verified and evaluated with a fixed authored indexed comprehension in one OPA call per registry. Exact complete count/order/index/schema and boolean/reason agreement remain mandatory, with the original ten-second process timeout and 64 KiB validated reply bound. Missing/duplicate/reordered/invalid/oversized/nonzero/timeout evidence fails closed. Invalid credentials remain denied in their original positions and never become privileged context. No arbitrary query/policy/plugin or provider environment is introduced. All original 55/80/120-second bounds are unchanged.

A genuine differential test evaluates all 256 decisions via both the original single-request API and the batch API. Every result agrees, with 256 cryptographic verifications per path and actual process counts of 256 versus two. One recorded same-test Windows observation measured 10,384.578 ms versus 272.970 ms. This is diagnostic, not a portable SLO, worst-case/p95 guarantee or attribution of the original delay. The new frozen nine-workflow/two-process journey passed under the unchanged deadlines; a final clean-source build must separately bind the commit.

## Observed local validation

- 188 source tests passed, one explicit Windows omission of the POSIX-only FIFO control; 95.85% combined coverage against the unchanged 95% floor at this observation.
- Strict Windows/Linux mypy, Ruff and locked dependency consistency passed.
- Original native Rego: 20/20; original provider-free Terraform: six tests, formatting and validation passed, with no backend/provider/apply.
- Exact locked browser model: 23 unit cases, TypeScript build/types, formatting/maps passed. All 16 original reader journeys passed across Chromium, Firefox, WebKit and mobile Chromium, with the original loopback-origin/no-outside-requests checks unchanged. The local private wrapper used the patched Python environment; final source/main observations remain separate.
- Full Python development/native and npm graphs reported zero known advisories at observation. Those package-manager checks do not audit Go modules embedded in OPA.
- Actual frozen candidate checks cover expected allows/denials, MFA, cross-tenant and exact emergency expiry, revocation, 128-context/256-decision review with four gains/three losses, the original 31-case suite, a changed external registry producing a visible mismatch, exact exports, invalid-input retention and identical nine-bundle restart. Known owned PIDs must exit normally; failed profiles are retained instead of recursively deleted beneath an active child.

## Native engine provenance and limits

Official [OPA1.22.3](https://github.com/open-policy-agent/opa/releases/tag/v1.22.3) Windows binary: 64,722,944 bytes; SHA256 `01fb91eedf7cfd53ffc308d828af19c86dc1f3e4f0b86c69fe8f3ce2699a7d83`. GitHub's immutable asset digest and upstream checksum sidecar agree. Linux/macOS existing tool pins were updated from their own verified official assets; that is not proof of native desktop packaging on those systems.

The actual Windows executable reports Go 1.27.3, upstream revision `32b01b6b3268531be9fb1c37be2c7788f6afc08e-dirty`, and links `github.com/klauspost/compress v1.20.3`, `github.com/lestrrat-go/jwx/v3 v3.4.0` and `golang.org/x/net v0.60.0`. The upstream dirty label is recorded literally and is independent of this app's own source-dirty gate. Linked-module license texts were collected at exact official Go mirror versions; the two unindexed genproto modules use their exact source pseudo-version commit. The 84-module inventory and runtime notices are retained, without upstream build host paths.

[GO-2026-6860](https://pkg.go.dev/vuln/GO-2026-6860) and [GO-2026-6866](https://pkg.go.dev/vuln/GO-2026-6866) affect HTML Parse/Render before x/net0.62.0, including the residual linked version. This fixed JSON/Rego route exposes neither operation. [The zstd advisory](https://github.com/advisories/GHSA-fpmh-frq8-7rj8) concerns untrusted decompression; upstream's release notes state OPA handlers do not support zstd. These are bounded applicability observations, not whole-program vulnerability clearance or scanner suppressions. Reassess before exposing other OPA APIs/builtins/bundles.

Windows unsigned portable packaging is not an installer, production IdP, complete AWS authorization engine, real MFA challenge, encrypted/multiuser store or compliance certificate. Tests use fresh fictional profiles only, never existing user accounts, real cloud resources, installed shortcuts or Docker. No package/profile/cache artifact upload is added.
