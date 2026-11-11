# Installed Windows 1.1.1 validation · 11 November 2026

By Jason Stys. These observations refer to the independently downloaded, published **1.1.1** application built from `5f3b7c262174d814dcccdfe3c614c4aad74edc8f`. Historical 1.1.0 documents and release assets remain unchanged.

## Actual installed results

**Actual installed workflows: Passed.** Full original domain, review and export controls passed two normal native launches; all 9 saved bundles retained exact original bytes.

**Old-to-new profile: Passed.** The actual installed 1.1.0 app created a synthetic profile; installed 1.1.1 reopened it and retained all 9 exact bundles without reset.

**Source and distribution: Verified.** Exact-main workflows and processed CodeQL passed with zero open main alerts. Five downloaded assets and installed files matched their verified SHA-256 identities.

**PC and links: Verified.** Existing links were backed up and retargeted with settings retained. Normal profiles and Docker were unchanged; default-profile shortcut activation remains separately untested.

## User workflow and implementation

The [four-page illustrated guide](windows-application-guide-1.1.1.docx) contains two actual installed-app screenshots, a practical user journey, an immutable-source code excerpt and measured validation with operating limits. The [review manifest](windows-application-guide-1.1.1.json) binds the Word, screenshot, code-source and rendered-page hashes. All 40 final page contents across this batch were individually inspected; each Office package passed schema validation. Prepared data stays inside the actual application workflow.

## Installation, private data and limitations

Use the matching Windows EXE, checksum and notices from Releases; no system Python or terminal setup is needed.

Use the verified existing Desktop icon. Help explains formats and limits; Exit application closes the native owner. Back up the complete external profile after a normal exit.

Offline signed synthetic evidence and a fixed OPA query, not a cloud identity provider or enforcement service. Issuer MFA freshness is an assertion rather than live MFA verification. Bundled OPA module advisories retain their scoped nonreachability assessment; no scanner-wide clearance is claimed.

Prepared workflows used synthetic profiles only. Ordinary user profiles and Docker were unchanged; local plaintext remains accessible to the OS owner/administrator. Profile alias checks do not defend against malicious code with the same OS privileges.

The actual installed 1.1.0 app created the synthetic profile used for the 1.1.1 upgrade test. Saved evidence retained exact bytes after the new app reopened it; no normal user profile was opened or reset. Desktop and Start-menu links were backed up and retargeted, retaining other settings. Target/arguments/read-back verification is distinct from default-profile shortcut activation, which was not independently exercised. Docker was unchanged. This documentation change requires its own full hosted checks; the runtime observations do not certify later source changes.
