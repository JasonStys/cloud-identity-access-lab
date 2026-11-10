# Documentation refresh — 2026-11-09

By Jason Stys.

This documentation-only edition describes source `2ffe676fb9ba49ced2902398062cef1ae8f7a5ae`. It does not change application behavior, accounts, private data, installers or published releases.

## Published editions and completed review

| File | Bytes | SHA-256 | Reviewed scope |
| --- | ---: | --- | --- |
| [project-guide.docx](project-guide.docx) | 44434 | `4e55460967656009c358e965766c446f5d8cf9f3b694ba79a29cab1518a1fec2` | 4 pages, each viewed individually |

Word review checked plain black titles, readable pagination, whole table rows, source references, practical limits and absence of clipping or overflow. Render receipts were matched to the current DOCX digest before approval.

## Evidence and change boundary

- Functional baseline: `2ffe676fb9ba49ced2902398062cef1ae8f7a5ae`.
- Workflow observation: `2026-11-10T05:25:40.628667+00:00`; exact run URLs and source identities remain in [publications.json](publications.json).
- Local document-package validation verifies exact copied bytes, Office ZIP integrity, approved page/tab identities and internal documentation links. Repository-specific documentation and source-policy commands are run separately and recorded in the integration handoff.
- Source/index metadata is regenerated using the repository’s existing tools. Existing privacy, security, coverage and workflow gates are retained.
- PR and later main workflows must pass independently. This record does not claim future or unrun integration CI success.

## Interpretation

The Word files document the cited source; dated source reports retain their original execution scope. A passing workflow is distinct from completed analysis with zero findings, and neither establishes production suitability. Checksums identify exact bytes, not a signature or publisher attestation.

Use the [handbook](../handbook.md) to choose usage, design, security and test documentation. Keep editable Markdown and reviewed editions together; do not replace historical measurements with undated claims.

## Integration-local checks

Observed at `2026-11-10T07:58:41.066022+00:00` on Windows with this repository’s existing development tools. Python commands use its isolated development environment. The documentation source baseline remains the immutable revision above; these checks validate this documentation integration locally.

| Command | Observed result |
| --- | --- |
| `python scripts/code_map.py` | Passed, exit 0. |
| `python scripts/file_guide.py` | Passed, exit 0. |
| `python scripts/code_map.py --check` | Passed, exit 0. |
| `python scripts/file_guide.py --check` | Passed, exit 0. |
| `python -m ruff check .` | Passed, exit 0. |
| `python -m ruff format --check .` | Passed, exit 0. |
| `python -m mypy` | Passed, exit 0. |
| `python -m pytest --cov --cov-report=term-missing` | Passed, exit 0. |

The independent publication audit also matched every copied Office file to its approved SHA-256, checked ZIP package integrity and current page/tab approvals, compared immutable workflow/source metadata, and resolved every local handbook/report link within the repository. Hosted PR/main, browser, platform and container jobs remain separate required checks; they are not inferred from these local results.



The existing full Python suite passed 93 tests with its installed genuine native OPA process and test-owned loopback HTTP service. The first sandboxed attempt denied those process/socket boundaries; a complete unchanged rerun with narrowly scoped execution access passed. The .NET session, Terraform, browser and provider-free native policy jobs remain separate hosted checks, not inferred from this documentation-only local run.

## Hosted checker correction

The first documentation PR run exposed a real repository integration gap after its functional tests passed: the tracked-source privacy checker decoded the new reviewed Word ZIP as UTF-8 text. This was a source-checker defect, not a GitHub runner failure. [Original failing run](https://github.com/JasonStys/cloud-identity-access-lab/actions/runs/42779210062) preserves that observation. The checker now reads XML and relationship text only for the exact `docs/reports/project-guide.docx` path. The original credential scan still inspects that text. Unknown binary paths retain strict rejection. The reader rejects duplicate/excess members, excessive expanded/XML bytes, missing Word parts, VBA and embedded objects, and checks ZIP integrity. No privacy, passive-runtime, provider-free, native or workflow gate was removed.

Ten independent tests use actual ZIP bytes to check accepted XML/relationships, real main-guard rejection of credentials in both document and relationship parts, unknown-filename rejection, and malformed/macro/embedded/oversize/duplicate packages. The complete local Python suite now passes 103 tests at the unchanged runtime coverage floor. Existing Ruff, formatting, mypy, exact code maps, tracked-file guide and the previously omitted original `python scripts/validate_repo.py` gate all pass. Later hosted results remain separate required evidence.
