# Threat model and review boundaries

Author: Jason Stys. Assets are transient synthetic credentials, fixed fixture policy and trustworthy test evidence; no real users or cloud permissions.

| Threat | Implemented boundary / tests | Residual limit |
| --- | --- | --- |
| Forged/unsigned/key-confused JWT | pinned EdDSA key/issuer/audience/header profile and real crypto negatives | trusted issuer/key lifecycle; no live-provider enrollment |
| Duplicate/extra/future/expired claims | bounded strict profile and duplicate/time checks | trusted local clock; rollback denies availability |
| Cross-tenant/role injection | registry supplies tenant/actions; unknown/extra role claims rejected | operator controls registry; not arbitrary AWS IAM policy semantics |
| Missing/stale MFA | verified issuer amr/auth_time, exclusive freshness bound | no real factor challenge or phishing resistance demonstrated |
| Fork/branch/repository workload change | exact immutable registered subject, separate workload scope | real issuer/JWKS/provider attestation not connected |
| Stale revocation / emergency privilege | fingerprint revoke, sticky disable, bounded exclusive expiry/two approvers | process-local state, not durable/distributed or atomic concurrent enforcement |
| Engine/tool failure or tampering | pinned official downloads, installed-byte verification, fixed argv/timeout, nonzero operational error | OS/repo/tool lock trusted; not an arbitrary-code sandbox |
| XSS / input probing / telemetry | no credential inputs, strict evidence decode, text nodes, CSP, fixed GET routes, no remote assets | local HTTP, trusted host; no public gateway assurance |
| Evidence corruption or false pass | exact schema, expected-vs-observed truth property, canonical SHA256, malformed-output tests | hashes provide integrity comparison, not signing/nonrepudiation |
| Accidental deployment / data publication | provider-free plan-only HCL, no id-token/cloud actions; ignored state plus privacy/secret gates | ignore is not encryption; logs/security outputs separate storage |

No real data, tokens, provider accounts, enrollment factors or secrets should be put into fixture registry/configuration, browser or committed files. Keys are generated fresh in memory and never persisted. The local issuer is not a production identity service. Programmatic fixture overrides exist for signed negative tests only.

Do not expose the local HTTP viewer through a tunnel or reverse proxy. Before any real integration obtain specific authority, require trusted HTTPS/real token profiles, durable revocation, managed key lifecycle, actual cloud policy/resource enforcement review, logging controls and incident/rollback procedures. Tests and CodeQL are evidence of reviewed bounded implementations, not proof of no vulnerability or compliance certification.
