# Local setup, evidence, troubleshooting and safe teardown

Author: Jason Stys. Read the README first; use synthetic inputs only.

## Setup and native commands

Python 3.12+, Node 24+, x86-64 Windows/Linux/macOS. Hash-locked runtime/dev install, npm ci --ignore-scripts, build assets. Install OPA 1.21.2 and Terraform 1.16.5 with python -m cial.tooling opa/terraform. Native tool hashes are reviewed in tools.lock.json; installer doesn't alter global PATH. ARM platform support is intentionally not claimed.

cryptography 50.0.2 does not publish a macOS Intel wheel: that platform builds the hash-pinned source distribution and may require Rust, C compiler and OpenSSL/libffi prerequisites. The hosted Intel lane verifies that source build in its equipped runner, not a dependency-free local install. Follow [upstream installation instructions](https://cryptography.io/en/latest/installation/); never bypass hashes or downgrade security checks to avoid setup work.

PowerShell:

    .venv/Scripts/python -m cial.tooling opa
    .venv/Scripts/python -m cial.tooling terraform
    .tools/opa.exe fmt --fail policy
    .tools/opa.exe check --strict policy
    .tools/opa.exe test policy -v
    .tools/terraform.exe -chdir=infra fmt -check -recursive
    .tools/terraform.exe -chdir=infra init -backend=false -input=false
    .tools/terraform.exe -chdir=infra validate
    .tools/terraform.exe -chdir=infra test
    .venv/Scripts/python -m pytest --cov=cial
    .venv/Scripts/python -m cial run --out out/new-evidence
    .venv/Scripts/python -m cial serve

Linux/macOS: use .venv/bin/python and native tool names without.exe. Native Terraform has no provider/backend/resource and all test runs command=plan. Do not add apply or real cloud privileges to validation.

## Evidence and UI

Run reports must use a new output directory; preserve earlier failure evidence rather than overwrite it. Downloaded JSON/HTML contains only synthetic summaries; hash corresponds to exact canonical JSON bytes. Browser search affects display only. “Denied access” and “failed regression” are distinct filters.

Serve starts only its own numeric-loopback listener after genuine matrix acceptance. It computes a fixed report once, not on every browser request. Ctrl+C closes the owned listener through its context manager. Browser CI owns/stops its own webserver; reuseExistingServer=false prevents silently testing another process.

## Failures and rollback

Missing/changed tool hashes: inspect the official source/version/digest, then reinstall only the named tool; never bypass verification or point to an arbitrary executable. Native engine error is an operational failure, not an expected authorization denial. No raw JWT or crypto error strings should be logged. Check installed runtimes/assets/input contracts rather than weaken checks.

Windows command-sandbox restrictions can prevent the verified Go OPA binary/Firefox launching. Trusted test execution outside that command sandbox can diagnose this without changing OS/browser/TLS protections. Do not repair Docker or disable antivirus. Hosted native lanes independently verify supported platforms.

Preserve the worktree/evidence; revert a reviewed source change in a new commit and rerun all gates. No production deployment/rollback exists. Changing bind addresses, adding actual providers, deleting Actions runs or changing billing requires separate authority. Ignored out/.tools/.venv/dist data is not encrypted.
