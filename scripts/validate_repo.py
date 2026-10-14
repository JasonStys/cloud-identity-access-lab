"""Jason Stys: repository privacy/action pins, provider-free infrastructure, exact documentation and native-tool limits."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# variable: ROOT — line 24
# definition: main — line 27
# variable: names — line 29
# variable: name — line 36
# variable: path — line 37
# variable: text — line 43
# variable: target — line 48
# variable: action — line 54
# variable: word — line 58
# variable: frontend — line 73
# variable: word — line 76
# variable: lock — line 78
# variable: item — line 79
# variable: name — line 79
# END CODE MAP

import json
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    """Inspect all tracked files; fail on private state, dangling links, mutable actions or accidental cloud deployment."""
    names = (
        subprocess.check_output(["git", "ls-files", "-z"], cwd=ROOT)
        .decode()
        .rstrip("\0")
        .split("\0")
    )
    assert names != [""], "Stage reviewed files before validation"
    for name in names:
        path = ROOT / name
        assert path.is_file()
        assert not name.startswith(
            ("out/", "dist/", ".tools/", ".venv/", "node_modules/")
        )
        assert not re.search(r"\.(?:pem|key|token|env|tfstate|tfplan)(?:$|[.-])", name)
        text = path.read_text(encoding="utf-8")
        assert not re.search(
            r"(?:ghp_|github_pat_)[A-Za-z0-9]{20,}|BEGIN [A-Z ]*PRIVATE KEY", text
        )
        if name.endswith(".md"):
            for target in re.findall(r"\]\(([^)]+)\)", text):
                if not target.startswith(("http:", "https:", "#", "mailto:")):
                    assert (path.parent / target.split("#")[0]).is_file(), (
                        name + ": " + target
                    )
        if name.startswith(".github/workflows/"):
            for action in re.findall(r"uses:\s*([^\s#]+)", text):
                assert re.fullmatch(r"[\w/.-]+@[a-f0-9]{40}", action)
                assert not any(
                    word in action
                    for word in (
                        "upload-artifact",
                        "download-artifact",
                        "actions/cache",
                        "configure-aws-credentials",
                    )
                )
            assert (
                "persist-credentials: false" in text and "id-token: write" not in text
            )
        if name.endswith((".tf", ".hcl")):
            assert not re.search(
                r"^\s*(?:provider|resource|data|backend)\s+\"", text, re.M
            )
            assert not re.search(r"command\s*=\s*apply", text)
    frontend = (ROOT / "web/app.ts").read_text() + (ROOT / "web/model.ts").read_text()
    assert not any(
        word in frontend
        for word in ("innerHTML", "outerHTML", "insertAdjacentHTML", "eval(")
    )
    lock = json.loads((ROOT / "package-lock.json").read_text())
    assert all("integrity" in item for name, item in lock["packages"].items() if name)
    assert "--hash=sha256:" in (ROOT / "requirements-dev.lock").read_text()
    assert (
        json.loads((ROOT / "policy/registry.json").read_text())["lab"]["synthetic"]
        is True
    )
    print(f"Privacy/pin/provider-free/link gates: {len(names)} tracked files passed")


if __name__ == "__main__":
    main()
