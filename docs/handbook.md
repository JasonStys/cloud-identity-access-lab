# Cloud Identity Access Lab handbook

By Jason Stys.

Examine synthetic identity and permission relationships, explain effective access and compare proposed policy changes. Results depend on the supplied snapshot and do not grant, revoke or collect live cloud permissions.

Compare signed native OPA policy decisions across MFA, expiry and registry-bound contexts.

Explains gained and lost access using authenticated synthetic evidence without changing cloud permissions.

## Read the documentation

| Edition | Audience and contents |
| --- | --- |
| [project-guide.docx](reports/project-guide.docx) | User and developer guide: purpose, current usage, design, boundaries and source references. |

The editable Markdown remains the maintenance source. The Word files are readable editions. See [publication identities and review](reports/publications.json) and the [documentation refresh record](reports/documentation-refresh-2026-11-09.md).

## Current usage and help

[README quick start](../README.md) is the entry point. Use the project-specific guides below before changing inputs, operating modes or deployment assumptions.

### Usage and operations

- [runbook](runbook.md)

### Design and contracts

- [architecture](architecture.md)
- [contracts](contracts.md)
- [research](research.md)

### Security and validation

- [security](security.md)
- [testing](testing.md)

## Historical results and reproduction

The reviewed source is [`2ffe676fb9ba49ced2902398062cef1ae8f7a5ae`](https://github.com/JasonStys/cloud-identity-access-lab/tree/2ffe676fb9ba49ced2902398062cef1ae8f7a5ae). The observed functional workflow baseline is `2ffe676fb9ba49ced2902398062cef1ae8f7a5ae`; those observations are recorded at `2026-11-10T05:25:40.628667+00:00`. They do not certify an unrun later revision.

- [Detailed recorded validation](reports/recertification-2026-11-09.md)
- [Current Actions](https://github.com/JasonStys/cloud-identity-access-lab/actions) records later integration checks separately.
- Preserve dated measurements and follow the existing testing guide to reproduce them; a test-source inventory alone does not establish execution.

## Practical boundaries

- Permissions reflect a fixed synthetic Rego model, not real cloud login or effective provider authorization.
- MFA contexts are signed assertions, not proof that an actual challenge was completed.
- Registry/context signature checks do not change real cloud permissions or establish every deployed identity control.

## Maintaining these editions

Update the editable usage/design/test documents first. Rebuild and visually review every Word page and workbook tab before replacing an edition; verify the exact binary digests and evidence source in publications.json. Keep account data, logs with secrets, installed-app state and private test stores out of documentation. Source and release assets retain their existing security and licensing boundaries.
