# Native signed-identity workbench

Created by Jason Stys. Version 1.1.0 adds an actual Windows portable application around the existing cryptographic verifier and native OPA engine. This is an owner-local synthetic security-engineering lab, not production account authentication or a cloud authorization proxy.

## Launch and use

Open `CloudIdentityAccessLab.exe`. No separately installed Python, Node, OPA, account, password or first-launch download is required. Inputs, Findings and Saved analyses tabs provide the actual workflows; Help, bundled Licenses and Exit application stay reachable. State is outside the executable in the version-independent OS-local `JasonStys/CloudIdentityAccessLab` application-data directory. The original CLI and TypeScript browser viewer remain supported separately.

Prepared scenarios fill ordinary fields without signing, evaluating or saving automatically. Review the inputs, acknowledge permission and Run. All outcomes come from actual signatures and the pinned OPA executable; a desired allow/deny value is only a regression oracle, never a grant.

### Evaluate a signed synthetic request

Choose a supported synthetic registry JSON, a subject, action, resource and explicit evaluation time in integer Unix seconds. The registry is data only: at most eight principals, four fixed resources, bounded action ceilings and a scoped two-approver emergency grant. An unknown subject remains denied. Neither fields nor files can select executable code, a query, external policy or a URL.

Choose a fresh, absent or stale issuer-attested MFA profile and a controlled credential condition: valid, expired, revoked, subject disabled, wrong signing key or backward clock. The app generates a fresh in-memory Ed25519 issuer/token and runs the original verifier. This demonstrates profile/signature/lifecycle enforcement, not real login, MFA enrollment or a completed challenge. Keys, signed tokens and raw claims never enter saved report bundles. Reports retain only selected synthetic context, expected/observed decision, reason and exact canonical registry/fixed-policy identities.

The emergency window is inclusive at start and exclusive at expiry. The explicit clock is not replaced by this PC's current time. A mismatch remains a mismatch when an edited registry removes permission; the app does not rewrite the oracle to manufacture a pass.

### Compare proposed entitlements

Choose baseline and proposed closed-schema registry files and an as-of time. The existing recertification engine enumerates subjects × both MFA contexts × four actions × four resources. A union larger than eight subjects rejects. It verifies every signed context and reports real gains, losses, candidate entitlements, emergency state/remaining time, canonical input hashes, fixed Rego hash and true denominators. No registry or cloud setting is applied.

The two registries now use two bounded native OPA batch calls instead of one process per decision. Every token is still individually verified. The authored query includes an exact context index; output must contain every ordered index, correct count and the original closed boolean/reason schema. No missing, duplicate, reordered, malformed or timed-out response becomes partial successful evidence. Each process keeps its original ten-second timeout, validated 64 KiB reply limit and a minimal OS environment without provider/Python/Node keys. The original 120-second comparison budget remains.

For the prepared tenant-move/publisher-removal example, 128 contexts produce 256 policy decisions, four gains and three losses. Separate MFA labels prevent apparently identical table rows from hiding different issuer-assurance contexts. These generic Rego permissions are not a complete AWS IAM evaluation.

### Original assurance suite

The third operation executes the original 31 cryptographic/policy scenarios with their original fixed registry and clock. Signature, audience, issuer, expiry, role substitution, workload branch/repository, revocation, MFA, emergency and rollback negatives remain actual executable checks. A frozen application needs no Git command to label its source: its verified package identity supplies the source SHA. The source CLI still has its original Git/uncommitted behavior.

## Inspect, retain and export

Select a view and use literal search to filter the current saved evidence; select a row for full copyable context. Saved analyses reopens the exact hash-verified bundle without issuing a new credential or rerunning OPA. Export creates a new directory under a selected private parent and never overwrites prior files. Explicit confirmed history removal affects only that selected local bundle, not inputs or prior exports.

One OS lock owns a marked profile. History is plaintext OS-owner data, not multiuser authentication or encryption: 20 runs/128 MiB retained payload, 64 MiB/bundle and 32 MiB/file, plus metadata overhead. Capacity fails without automatic eviction. Back up the complete profile after clean Exit. Exit drains the owned worker/process calls; it does not kill other apps or change system/cloud settings.

## Runtime and distribution boundaries

The portable recipe requires patched Windows CPython 3.14.10 and binds the actual interpreter DLL, source/dirty state, icon/notices, fixed policy/registries and official OPA bytes. OPA has a separate 128 MiB executable-resource bound and streaming hash; evidence/history limits are unchanged. The official immutable OPA 1.22.3 asset is checked against its provider digest and checksum sidecar. It reports Go1.27.3 and an upstream `-dirty` build label; that upstream label is distinct from this repository's own clean/dirty state.

Actual Python/Tcl/Tk/cryptography/JWT/FFI notices and texts for all 84 linked Windows OPA Go modules are included and accessible through Licenses. An inventory is not vulnerability or legal clearance. OPA1.22.3 still embeds `golang.org/x/net v0.60.0`; the known HTML Parse/Render advisories affect that version. This application's fixed JSON-only query/data route does not expose HTML parsing/rendering or untrusted zstd, and no general reachability-clearance claim is made. See the [dated validation and provenance report](reports/native-workbench-2026-11-10.md).

The app adds no OPA server, external identity exchange, JWKS fetch, real MFA, provider login, AWS request, Terraform apply or live enforcement. Original provider-free Terraform and browser tests remain separate gates. Windows acceptance does not establish a Mac/Linux portable package or an Authenticode signature.
