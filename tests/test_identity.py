"""Jason Stys: real signature/token-profile negatives, time properties and revocation boundaries."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# definition: issuer — line 63
# definition: test_signed_token_and_revocation — line 68
# parameter: issuer — line 68
# variable: verifier — line 70
# variable: first — line 71
# variable: peer — line 72
# variable: identity — line 73
# definition: test_signed_invalid_profiles — line 114
# parameter: claims — line 114
# parameter: issuer — line 114
# definition: test_malformed_transport — line 123
# parameter: issuer — line 123
# parameter: token — line 123
# definition: test_header_key_algorithm_and_duplicate_claims — line 129
# parameter: issuer — line 129
# variable: token — line 131
# variable: claims — line 132
# variable: verifier — line 133
# variable: headers — line 134
# variable: algorithm — line 142
# variable: key — line 142
# variable: raw — line 150
# variable: duplicate — line 151
# definition: test_expiry_mfa_and_rollback — line 164
# parameter: issuer — line 164
# variable: verifier — line 166
# variable: token — line 167
# definition: test_revocation_capacity_and_expired_reclamation — line 186
# parameter: issuer — line 186
# variable: verifier — line 188
# variable: index — line 189
# variable: index — line 196
# definition: test_time_property — line 204
# parameter: elapsed — line 204
# parameter: lifetime — line 204
# variable: issuer — line 206
# variable: verifier — line 207
# variable: token — line 208
# END CODE MAP

import json

import jwt
import pytest
from hypothesis import given
from hypothesis import strategies as st

from cial.identity import (
    AUDIENCE,
    ISSUER,
    KID,
    FixtureIssuer,
    Identity,
    Rejected,
    Verifier,
)
from cial.scenarios import NOW


@pytest.fixture
def issuer():
    """Create one fresh native Ed25519 fixture issuer per test; never write its private key."""
    return FixtureIssuer()


def test_signed_token_and_revocation(issuer):
    """Verify genuine signatures and ensure target revocation does not revoke peer tokens or expose raw IDs."""
    verifier = Verifier(issuer.public_key)
    first = issuer.issue("engineer-alpha", NOW)
    peer = issuer.issue("engineer-alpha", NOW)
    identity = verifier.verify(first, NOW)
    assert identity.subject == "engineer-alpha" and identity.mfa_fresh
    assert len(identity.fingerprint) == 64 and first != peer
    verifier.revoke(identity)
    with pytest.raises(Rejected):
        verifier.verify(first, NOW)
    assert verifier.verify(peer, NOW).subject == identity.subject
    verifier.disable(identity.subject)
    with pytest.raises(Rejected):
        verifier.verify(peer, NOW)


@pytest.mark.parametrize(
    "claims",
    [
        {"aud": "other"},
        {"aud": [AUDIENCE]},
        {"iss": ISSUER + "/"},
        {"sub": ""},
        {"sub": "../private?"},
        {"iat": NOW + 1},
        {"iat": True},
        {"nbf": NOW + 1},
        {"nbf": NOW - 1},
        {"nbf": "1"},
        {"exp": NOW},
        {"exp": NOW + 301},
        {"exp": NOW + 0.5},
        {"auth_time": NOW + 1},
        {"auth_time": -1},
        {"auth_time": "1"},
        {"token_use": "id"},
        {"jti": "chosen"},
        {"amr": []},
        {"amr": ["unknown"]},
        {"amr": True},
        {"amr": ["pwd"] * 5},
        {"role": "admin"},
        {"tenant": "beta"},
    ],
)
def test_signed_invalid_profiles(issuer, claims):
    """Signed but invalid claims must not be trusted simply because the cryptographic signature is valid."""
    with pytest.raises(Rejected):
        Verifier(issuer.public_key).verify(
            issuer.issue("engineer-alpha", NOW, **claims), NOW
        )


@pytest.mark.parametrize("token", ["", "not-token", "a.b.c", "é", "x" * 4097, None, 12])
def test_malformed_transport(issuer, token):
    """Malformed/oversized/nonstring transport fails in bounded verification without private error details."""
    with pytest.raises(Rejected, match="credential_rejected"):
        Verifier(issuer.public_key).verify(token, NOW)


def test_header_key_algorithm_and_duplicate_claims(issuer):
    """Reject key URL injection, unknown kid, unsigned/HMAC tokens, key mismatch and duplicate JSON fields."""
    token = issuer.issue("engineer-alpha", NOW)
    claims = jwt.decode(token, options={"verify_signature": False})
    verifier = Verifier(issuer.public_key)
    for headers in [
        {"kid": "unknown"},
        {"kid": KID, "jku": "https://outside.example.invalid"},
    ]:
        with pytest.raises(Rejected):
            verifier.verify(
                jwt.encode(claims, issuer._key, algorithm="EdDSA", headers=headers), NOW
            )
    for algorithm, key in [
        ("none", ""),
        ("HS256", "synthetic-only-key-of-at-least-32-characters"),
    ]:
        with pytest.raises(Rejected):
            verifier.verify(jwt.encode(claims, key, algorithm=algorithm), NOW)
    with pytest.raises(Rejected):
        verifier.verify(FixtureIssuer().issue("engineer-alpha", NOW), NOW)
    raw = json.dumps(claims)[:-1] + ',"sub":"responder-alpha"}'
    duplicate = jwt.api_jws.encode(
        raw.encode(), issuer._key, algorithm="EdDSA", headers={"kid": KID, "typ": "JWT"}
    )
    with pytest.raises(Rejected):
        verifier.verify(duplicate, NOW)
    del claims["jti"]
    with pytest.raises(Rejected):
        verifier.verify(
            jwt.encode(claims, issuer._key, algorithm="EdDSA", headers={"kid": KID}),
            NOW,
        )


def test_expiry_mfa_and_rollback(issuer):
    """Prove exclusive expiry/MFA boundaries and fail-closed clock rollback, without sleeps or wall-clock mocks."""
    verifier = Verifier(issuer.public_key)
    token = issuer.issue("engineer-alpha", NOW, auth_time=NOW - 299)
    assert verifier.verify(token, NOW).mfa_fresh
    assert not verifier.verify(token, NOW + 1).mfa_fresh
    with pytest.raises(Rejected, match="clock"):
        verifier.verify(token, NOW)
    with pytest.raises(Rejected):
        Verifier(issuer.public_key).verify(token, -1)
    with pytest.raises(Rejected):
        Verifier(issuer.public_key).verify(token, True)
    assert Verifier(issuer.public_key).verify(token, NOW + 119)
    with pytest.raises(Rejected):
        Verifier(issuer.public_key).verify(token, NOW + 120)
    assert (
        not Verifier(issuer.public_key)
        .verify(issuer.issue("engineer-alpha", NOW, mfa=False), NOW)
        .mfa_fresh
    )


def test_revocation_capacity_and_expired_reclamation(issuer):
    """Capacity must fail rather than evict a live revocation; expired fingerprints can be reclaimed."""
    verifier = Verifier(issuer.public_key)
    for index in range(256):
        verifier.revoke(Identity("subject", False, NOW + 1, str(index)))
    verifier.revoke(Identity("subject", False, NOW + 1, "0"))
    with pytest.raises(Rejected, match="capacity"):
        verifier.revoke(Identity("subject", False, NOW + 1, "new"))
    verifier.verify(issuer.issue("engineer-alpha", NOW + 1), NOW + 1)
    verifier.revoke(Identity("subject", False, NOW + 2, "new"))
    for index in range(256):
        verifier.disable(str(index))
    verifier.disable("0")
    with pytest.raises(Rejected, match="capacity"):
        verifier.disable("new")


@given(st.integers(min_value=1, max_value=300), st.integers(min_value=0, max_value=301))
def test_time_property(lifetime, elapsed):
    """For every valid bounded lifetime, acceptance is exactly the interval before expiry."""
    issuer = FixtureIssuer()
    verifier = Verifier(issuer.public_key)
    token = issuer.issue("engineer-alpha", NOW, exp=NOW + lifetime)
    if elapsed < lifetime:
        assert verifier.verify(token, NOW + elapsed).expires == NOW + lifetime
    else:
        with pytest.raises(Rejected):
            verifier.verify(token, NOW + elapsed)
