"""Jason Stys: independent real-ZIP publication privacy boundary and unknown-file rejection regressions."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# definition: write_document — line 51
# parameter: content — line 52
# parameter: extra — line 52
# parameter: root — line 52
# variable: path — line 55
# variable: package — line 57
# variable: name — line 61
# variable: value — line 61
# definition: test_actual_word_xml_and_relationships_remain_inspected — line 69
# parameter: filename — line 70
# parameter: monkeypatch — line 70
# parameter: tmp_path — line 70
# variable: path — line 74
# variable: path — line 77
# variable: result — line 78
# definition: test_actual_main_still_rejects_credentials_in_word_parts — line 84
# parameter: monkeypatch — line 85
# parameter: part — line 85
# parameter: tmp_path — line 85
# variable: token — line 88
# parameter: args — line 101
# parameter: kwargs — line 101
# definition: test_only_exact_reviewed_filename_receives_office_handling — line 107
# parameter: monkeypatch — line 107
# parameter: tmp_path — line 107
# variable: path — line 110
# variable: unknown — line 111
# variable: source — line 115
# definition: test_unsupported_or_unbounded_real_packages_fail — line 124
# parameter: defect — line 124
# parameter: monkeypatch — line 124
# parameter: tmp_path — line 124
# variable: extras — line 127
# variable: extras — line 135
# variable: i — line 135
# variable: path — line 136
# variable: package — line 138
# variable: package — line 143
# END CODE MAP

from pathlib import Path
from zipfile import ZipFile

import pytest

from scripts import validate_repo as policy


def write_document(
    root: Path, content: str, extra: dict[str, str] | None = None
) -> Path:
    """Create actual small ZIP bytes independently of the production reader."""
    path = root / "docs/reports/project-guide.docx"
    path.parent.mkdir(parents=True)
    with ZipFile(path, "w") as package:
        package.writestr("[Content_Types].xml", "<Types/>")
        package.writestr("word/document.xml", content)
        package.writestr("word/_rels/document.xml.rels", "<Relationships/>")
        for name, value in (extra or {}).items():
            package.writestr(name, value)
    return path


@pytest.mark.parametrize(
    "filename", ["project-guide.docx", "windows-application-guide-1.1.1.docx"]
)
def test_actual_word_xml_and_relationships_remain_inspected(
    tmp_path, monkeypatch, filename
):
    """A real ZIP yields its XML and relationship text, not a metadata placeholder."""
    monkeypatch.setattr(policy, "ROOT", tmp_path)
    path = write_document(
        tmp_path, "<document>Read the scoped source evidence.</document>"
    )
    path = path.rename(path.with_name(filename))
    result = policy.public_text(path)
    assert "Read the scoped source evidence." in result
    assert "<Relationships/>" in result and "<Types/>" in result


@pytest.mark.parametrize("part", ["document", "relationship"])
def test_actual_main_still_rejects_credentials_in_word_parts(
    tmp_path, monkeypatch, part
):
    """Run the genuine existing credential guard over actual ZIP XML/relationships before later gates."""
    token = "ghp_" + "A" * 32
    monkeypatch.setattr(policy, "ROOT", tmp_path)
    if part == "document":
        write_document(tmp_path, "<document>" + token + "</document>")
    else:
        write_document(
            tmp_path,
            "<document>Public.</document>",
            {"_rels/.rels": "<Relationship Target='" + token + "'/>"},
        )
    monkeypatch.setattr(
        policy.subprocess,
        "check_output",
        lambda *args, **kwargs: b"docs/reports/project-guide.docx\0",
    )
    with pytest.raises((AssertionError, ValueError), match="possible credential"):
        policy.main()


def test_only_exact_reviewed_filename_receives_office_handling(tmp_path, monkeypatch):
    """A renamed unknown DOCX remains rejected by strict UTF-8 handling; ordinary source stays readable."""
    monkeypatch.setattr(policy, "ROOT", tmp_path)
    path = write_document(tmp_path, "<document>Public.</document>")
    unknown = path.with_name("unreviewed.docx")
    unknown.write_bytes(path.read_bytes() + b"\xff")
    with pytest.raises(UnicodeDecodeError):
        policy.public_text(unknown)
    source = tmp_path / "source.md"
    source.write_text("Public source.", encoding="utf-8")
    assert policy.public_text(source) == "Public source."


@pytest.mark.parametrize(
    "defect",
    ["missing-main", "macro", "embedded", "xml-budget", "member-budget", "duplicate"],
)
def test_unsupported_or_unbounded_real_packages_fail(tmp_path, monkeypatch, defect):
    """Independent malformed ZIP fixtures cannot become uninspected accepted documentation."""
    monkeypatch.setattr(policy, "ROOT", tmp_path)
    extras = {}
    if defect == "macro":
        extras["word/vbaProject.bin"] = "inert test bytes"
    elif defect == "embedded":
        extras["word/embeddings/inert.bin"] = "inert test bytes"
    elif defect == "xml-budget":
        extras["word/extra.xml"] = "x" * (2 * 1024 * 1024)
    elif defect == "member-budget":
        extras = {f"word/part{i}.xml": "<x/>" for i in range(256)}
    path = write_document(tmp_path, "<document/>", extras)
    if defect == "missing-main":
        with ZipFile(path, "w") as package:
            package.writestr("[Content_Types].xml", "<Types/>")
    elif defect == "duplicate":
        with (
            pytest.warns(UserWarning, match="Duplicate name"),
            ZipFile(path, "a") as package,
        ):
            package.writestr("word/document.xml", "<document/>")
    with pytest.raises(ValueError):
        policy.public_text(path)
