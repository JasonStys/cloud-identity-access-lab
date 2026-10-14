"""Jason Stys: truthful report/property negatives and inert escaping, independent from native policy acceptance."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# definition: report — line 31
# definition: test_bad_rows — line 73
# parameter: field — line 73
# parameter: report — line 73
# parameter: value — line 73
# definition: test_shape_and_duplicates — line 80
# parameter: report — line 80
# variable: changed — line 82
# definition: test_inert_exports_and_verdict — line 101
# parameter: report — line 101
# variable: document — line 104
# definition: test_truth_property — line 118
# parameter: expected — line 118
# parameter: observed — line 118
# END CODE MAP

import copy
import math

import pytest
from hypothesis import given
from hypothesis import strategies as st

from cial.evidence import canonical, digest, passed, render, validate
from cial.identity import Rejected


@pytest.fixture
def report():
    """Small controlled verdict fixture, never a substitute for the actual native scenario matrix."""
    return {
        "schema": 1,
        "synthetic": True,
        "source": "uncommitted",
        "cases": [
            {
                "id": "TEST-ONE",
                "title": "Synthetic",
                "principal": "engineer-alpha",
                "action": "read",
                "resource": "alpha-docs",
                "expected": True,
                "observed": True,
                "reason": "allowed",
                "elapsed_ms": 1,
            }
        ],
    }


@pytest.mark.parametrize(
    "field,value",
    [
        ("id", "bad"),
        ("id", None),
        ("title", ""),
        ("title", "x" * 201),
        ("title", "x\n"),
        ("expected", 1),
        ("observed", "true"),
        ("action", "*"),
        ("resource", "*"),
        ("reason", "policy_denied"),
        ("elapsed_ms", True),
        ("elapsed_ms", -1),
        ("elapsed_ms", math.inf),
        ("elapsed_ms", math.nan),
        ("elapsed_ms", 60001),
    ],
)
def test_bad_rows(report, field, value):
    """No malformed values or contradictory observed reason can pass schema validation."""
    report["cases"][0][field] = value
    with pytest.raises(Rejected):
        validate(report)


def test_shape_and_duplicates(report):
    """Reject private extra fields, duplicate case IDs, invalid source and empty/oversized catalogs."""
    for changed in [
        None,
        [],
        {**report, "private": "token"},
        {**report, "schema": True},
        {**report, "synthetic": False},
        {**report, "source": "not-sha"},
        {**report, "cases": []},
        {**report, "cases": [report["cases"][0]] * 129},
        {**report, "cases": [report["cases"][0]] * 2},
        {**report, "cases": ["bad"]},
    ]:
        with pytest.raises(Rejected):
            validate(changed)
    report["cases"][0]["token"] = "private"
    with pytest.raises(Rejected):
        validate(report)


def test_inert_exports_and_verdict(report):
    """Hostile-looking labels remain escaped text; canonical bytes fingerprint exact evidence rather than timing promises."""
    report["cases"][0]["title"] = '<img src=x onerror="alert(1)">'
    document = render(report)
    assert (
        "&lt;img" in document and "<img" not in document and "<script" not in document
    )
    assert len(digest(report)) == 64 and canonical(report) == canonical(
        copy.deepcopy(report)
    )
    report["cases"][0].update(expected=False, observed=False, reason="policy_denied")
    assert passed(report["cases"][0])
    report["cases"][0]["expected"] = True
    assert not passed(report["cases"][0])


@given(st.booleans(), st.booleans())
def test_truth_property(expected, observed):
    """All four expected/observed combinations preserve the actual regression verdict."""
    assert passed({"expected": expected, "observed": observed}) == (
        expected == observed
    )
