"""Jason Stys: repository privacy/action pins, provider-free infrastructure, exact documentation and native-tool limits."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# variable: ROOT — line 37
# definition: public_text — line 40
# parameter: path — line 40
# variable: package — line 47
# variable: members — line 48
# variable: member — line 49
# variable: names — line 49
# variable: member — line 53
# variable: item — line 58
# variable: inspected — line 62
# variable: member — line 63
# variable: member — line 65
# variable: member — line 69
# definition: main — line 72
# variable: names — line 74
# variable: name — line 81
# variable: path — line 82
# variable: text — line 88
# variable: target — line 93
# variable: action — line 99
# variable: word — line 103
# variable: frontend — line 118
# variable: word — line 121
# variable: lock — line 123
# variable: item — line 124
# variable: name — line 124
# END CODE MAP

import json
import re
import subprocess
from pathlib import Path
from zipfile import ZipFile

ROOT = Path(__file__).resolve().parents[1]


def public_text(path: Path) -> str:
    """Inspect XML/relationships in exact reviewed Word editions; unknown binary files still fail closed."""
    if path.relative_to(ROOT).as_posix() not in {
        "docs/reports/project-guide.docx",
        "docs/reports/windows-application-guide-1.1.1.docx",
    }:
        return path.read_text(encoding="utf-8")
    with ZipFile(path) as package:
        members = package.infolist()
        names = [member.filename for member in members]
        if (
            len(members) > 256
            or len(set(names)) != len(names)
            or sum(member.file_size for member in members) > 8 * 1024 * 1024
            or "word/document.xml" not in names
            or "[Content_Types].xml" not in names
            or any(
                "vbaProject" in item or item.startswith("word/embeddings/")
                for item in names
            )
        ):
            raise ValueError("Invalid or unsupported reviewed Word package")
        inspected = [
            member for member in members if member.filename.endswith((".xml", ".rels"))
        ]
        if sum(member.file_size for member in inspected) > 2 * 1024 * 1024:
            raise ValueError("Reviewed Word XML exceeds inspection budget")
        if package.testzip() is not None:
            raise ValueError("Reviewed Word package integrity failed")
        return "\n".join(package.read(member).decode("utf-8") for member in inspected)


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
        text = public_text(path)
        assert not re.search(
            r"(?:ghp_|github_pat_)[A-Za-z0-9]{20,}|BEGIN [A-Z ]*PRIVATE KEY", text
        ), "possible credential in tracked source"
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
