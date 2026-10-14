# Identity, policy, evidence and infrastructure contracts

Author: Jason Stys. Closed synthetic example; unsupported profiles fail rather than guess.

## Signed credentials

Maximum 4,096 ASCII token characters. Fixed EdDSA/Ed25519 verification key, kid ephemeral-fixture-key and typ JWT; no extra JOSE headers, dynamic algorithms, remote jku/x5u/JWKS or symmetric fallback. Duplicate JSON keys reject before signature verification. PyJWT verifies the signature, exact issuer https://identity.example.invalid and single audience cloud-identity-access-lab.

Exact claims: iss/aud/sub/iat/nbf/exp/jti/amr/auth_time/token_use. Access-token profile only. NumericDates are integers, not booleans/floats; 0 ≤ auth_time ≤ iat ≤ now < exp; iat ≤ nbf ≤ now; lifetime 1–300 seconds. PyJWT's wall-clock temporal checks are replaced by these explicit trusted-clock checks, not omitted. Backward clock observations fail closed. Subject length1–180 restricted ASCII; jti32 lowercase hex. amr1–4 known strings. Human MFA freshness is strictly less than 300 seconds after auth_time.

Verifier returns only subject, MFA freshness, expiry and SHA256 jti fingerprint. No caller tenant/role is trusted. Up to256 live revocations and256 disabled subjects; capacity exhaustion rejects rather than evict live records. Expired revocations reclaim during verification. Disablement lasts the fixture lifetime, with no resurrection-prone re-enable shortcut.

## Native policy

Exact input: subject/mfa_fresh/now/action/resource. Fixed real Rego query data.cial.decision and trusted registry. Actions read/publish/delete/rotate, four exact synthetic resource IDs. Tenant equality, principal action and resource action ceilings must all hold. Delete never grants. Human non-read access requires fresh MFA; workload publish uses a separate exact registered immutable subject.

Rotate additionally requires trusted subject/action/resource grant equality, starts ≤ now < expires, duration1–900 seconds, exactly two distinct nonself approvers. Browser inputs cannot create or approve grants. Stable result allow boolean and matching allowed/policy_denied reason only. Credential failures deny; engine timeout/process/schema failures are operational errors, not recorded fake denials.

OPA executes without shell interpolation, fixed repo policy/data paths,10-second timeout and65,536-character output cap after execution. Reviewed policy/data and local operator are trusted; the cap is not a sandbox for arbitrary malicious Rego.

## Evidence/viewer

Schema1, synthetic true, source40 lowercase hex or honest uncommitted, cases1–128. Exact row fields, unique bounded IDs, expected/observed booleans, finite elapsed_ms0–60,000 and stable reason. A regression passes iff expected equals observed; an expected denial is a passing security test. Reports contain no JWTs/JTIs/key bytes/raw claims.

CLI run requires a new nonlinked output directory with existing parent, producing decisions.json/html/sha256. Serve computes native evidence once then exposes immutable fixed GET assets/results/health on127.0.0.1; no upload/login/token/cloud-operation route. Exact Host/Origin/fetch-site guards, no CORS, CSP/no-store/nosniff, finite5s socket timeout. This standard-library local server is not a hardened public gateway.

UI decodes the exact bounded schema before display, filters evidence only and uses text nodes. All downloads are synthetic sanitized evidence, not permission grants or private user files.

## Terraform scope

No provider, resource, data source, remote backend or apply test. Exact Terraform1.16.5. Synthetic account12 digits, one immutable GitHub branch subject (no wildcard/legacy/environment profile), exact simple bucket. Trust uses one StringEquals audience sts.amazonaws.com and subject, one provider ARN/action. Identity allows only PutObject on releases/*; example boundary allows that and explicitly denies DeleteObject. The object-prefix wildcard is intentional; it is not unrestricted trust. AWS IAM includes exceptions/interactions not implemented by this generic Rego lab.
