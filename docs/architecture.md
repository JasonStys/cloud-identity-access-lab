# ADR-001: signed local identity integration and native policy assurance without cloud changes

Status: accepted. Date: 2026-10-14. Author/decider: Jason Stys.

## Context and decision

Demonstrate identity integration, MFA assurance, least privilege, temporary credentials and revocation without an account that authorizes real cloud deployment. Use Python/PyJWT/cryptography for fixed-profile signed-credential verification; Rego/OPA for declarative policy; provider-free Terraform HCL for tested AWS IAM document generation; TypeScript for strict evidence contracts and accessible UI. Bash runs portable checks.

    Ephemeral synthetic issuer → signed access JWT
                                ↓
    Pinned signature/profile/time/revocation verifier
                                ↓
    Sanitized subject + MFA freshness + trusted time + access request
                                ↓
    Native OPA + authoritative registry → observed decision
                                ↓
    Strict expected/observed report → JSON / SHA256 / inert HTML / viewer

Terraform's plan-only document tests are independent: they verify exact AWS-shaped trust/policy output, not deployed AWS behavior or full IAM evaluation equivalence.

## Alternatives and tradeoffs

An unsigned claim simulator would not prove the identity-verification boundary. A real managed provider would add tenant enrollment, cloud/identity privileges, costs, MFA factors, TLS, signing-key lifecycle and operational responsibilities beyond this authorized task. A homemade JWT/crypto implementation would add unnecessary risk; established libraries perform cryptography. OPA process startup costs more than an embedded policy engine but makes native execution easy to inspect/test and avoids a decorative language wrapper.

The UI is a read-only evidence viewer, not a login or privilege editor. Missing engines/invalid evidence produce failure; no mocked fallback. Trusted data grants are not supplied by browser users. The architecture is deliberately single-host/single-operator and not distributed.

## Revisit before real deployment

Approved managed provider and access-token profile; stable issuer/discovery/JWKS pin/rotation; phishing-resistant MFA enrollment and attestation; explicit workload trust/issuer/audience; protected GitHub environments; trusted clock and HTTPS; durable distributed revocation with consistency model; audit privacy/retention; cloud policy validation against all relevant AWS IAM interactions; resource enforcement and rollback. Merely changing a bind address is not deployment readiness.
