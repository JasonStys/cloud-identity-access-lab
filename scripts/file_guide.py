"""Jason Stys: exact tracked-file README purpose inventory; unknown files fail instead of receiving guessed descriptions."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# variable: ROOT — line 30
# variable: BEGIN — line 31
# variable: END — line 31
# variable: SPECIAL — line 32
# definition: purpose — line 55
# parameter: name — line 55
# variable: text — line 59
# variable: line — line 73
# variable: line — line 82
# definition: main — line 88
# variable: parser — line 90
# variable: args — line 92
# variable: names — line 93
# variable: rows — line 101
# variable: name — line 102
# variable: path — line 112
# variable: original — line 113
# variable: end — line 114
# variable: start — line 114
# variable: expected — line 115
# END CODE MAP

import argparse
import ast
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BEGIN, END = "<!-- BEGIN FILE GUIDE -->", "<!-- END FILE GUIDE -->"
SPECIAL = {
    "policy/registry.json": "Authoritative synthetic principal/resource/emergency registry; no real identities.",
    "infra/main.tf": "Provider-free validated AWS trust, scoped identity and boundary document generator.",
    "infra/tests/policies.tftest.hcl": "Native plan-only Terraform trust/scope/invalid-input tests, no providers.",
    ".gitignore": "Exclude runtime tokens, databases, builds, compilers and working reports.",
    ".gitattributes": "Consistent LF checkouts across supported operating systems.",
    "LICENSE": "MIT license for authored code; upstream tools retain their licenses.",
    "global.json": "Exact .NET SDK 10.0.401, no automatic version roll-forward.",
    "package.json": "Exact browser tool graph and build/verification commands.",
    "package-lock.json": "Complete integrity-locked npm tool graph.",
    "pyproject.toml": "Strict Python evidence/conformance lint/type/95% combined coverage gates.",
    "tsconfig.json": "Strict browser compilation with unchecked-index/nullable safeguards.",
    "requirements-dev.in": "Exact Python development tool inputs.",
    "requirements-dev.lock": "Complete portable hash-locked Python development graph.",
    "tools.lock.json": "Pinned OPA/Terraform platform release URLs and SHA256 digests.",
    "services/session/packages.lock.json": "Locked framework-only server restore, no external NuGet packages.",
    "tests/session/packages.lock.json": "Locked framework-only native test restore.",
    "docs/reports/ci.json": "Immutable accepted-source Actions check snapshot, not a future guarantee.",
    "docs/reports/http.json": "Actual synthetic expected/observed native HTTP evidence, no cookies or raw input.",
    "docs/reports/http.html": "Inert escaped rendering of the synthetic HTTP evidence.",
}


def purpose(name: str) -> str:
    """Extract an authored purpose from the source header or an explicit non-commentable configuration map."""
    if name in SPECIAL:
        return SPECIAL[name]
    text = (ROOT / name).read_text(encoding="utf-8")
    if name.endswith(".py"):
        return (ast.get_docstring(ast.parse(text)) or "").splitlines()[0]
    if name.endswith(".md"):
        return text.splitlines()[0].lstrip("# ") + "."
    if name.endswith(".html") and name.startswith("web/"):
        return (
            "Responsive semantic local-only browser encoding exercise and scope/help."
        )
    if name.endswith(".csproj"):
        return text.splitlines()[0].removeprefix("<!-- ").removesuffix(" -->")
    if name.endswith((".sh", ".yml", ".sql", ".rego")):
        return next(
            line.lstrip("#- ")
            for line in text.splitlines()
            if line.startswith(("# ", "-- "))
        )
    if name.endswith((".ts", ".mjs", ".java", ".cs", ".php", ".css")):
        return next(
            line.removeprefix("/** ")
            .removeprefix("/* ")
            .removeprefix("// ")
            .removesuffix(" */")
            for line in text.splitlines()
            if "Jason Stys:" in line
        )
    raise ValueError("Tracked-file purpose missing: " + name)


def main() -> None:
    """Generate/check exact README summaries; stage only reviewed nonprivate files before generating."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    names = (
        subprocess.check_output(["git", "ls-files", "-z"], cwd=ROOT)
        .decode()
        .rstrip("\0")
        .split("\0")
    )
    if names == [""]:
        raise ValueError("Stage reviewed files first")
    rows = ["| File | Purpose |", "| --- | --- |"]
    for name in sorted(names):
        rows.append(
            "| ["
            + name.replace("_", "\\_")
            + "]("
            + name
            + ") | "
            + purpose(name).replace("|", "/")
            + " |"
        )
    path = ROOT / "README.md"
    original = path.read_text(encoding="utf-8")
    start, end = original.index(BEGIN) + len(BEGIN), original.index(END)
    expected = original[:start] + "\n\n" + "\n".join(rows) + "\n\n" + original[end:]
    if args.check and expected != original:
        raise ValueError("README guide stale")
    if not args.check:
        path.write_text(expected, encoding="utf-8", newline="\n")
    print("README complete inventory: " + str(len(names)))


if __name__ == "__main__":
    main()
