"""Jason Stys: pinned Ed25519 JWT verification, authoritative time bounds and in-memory credential revocation."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# variable: ISSUER — line 79
# variable: AUDIENCE — line 80
# variable: KID — line 81
# variable: CLAIMS — line 82
# definition: unique_pairs — line 96
# parameter: pairs — line 96
# variable: result — line 98
# variable: key — line 99
# variable: value — line 99
# definition: Rejected — line 106
# definition: Identity — line 111
# variable: subject — line 114
# variable: mfa_fresh — line 115
# variable: expires — line 116
# variable: fingerprint — line 117
# definition: FixtureIssuer — line 120
# definition: __init__ — line 123
# parameter: self — line 123
# attribute: _key — line 125
# definition: public_key — line 128
# parameter: self — line 128
# definition: issue — line 132
# parameter: mfa — line 133
# parameter: now — line 133
# parameter: overrides — line 133
# parameter: self — line 133
# parameter: subject — line 133
# variable: claims — line 136
# definition: Verifier — line 154
# definition: __init__ — line 157
# parameter: key — line 157
# parameter: self — line 157
# attribute: _key — line 159
# attribute: _revoked — line 160
# attribute: _disabled — line 161
# attribute: _last_now — line 162
# definition: verify — line 164
# parameter: now — line 164
# parameter: self — line 164
# parameter: token — line 164
# attribute: _last_now — line 168
# variable: segments — line 172
# variable: segment — line 175
# variable: header — line 180
# variable: claims — line 185
# variable: field — line 205
# variable: methods — line 222
# variable: item — line 228
# variable: fingerprint — line 232
# attribute: _revoked — line 233
# variable: expiry — line 234
# variable: key — line 234
# definition: revoke — line 245
# parameter: identity — line 245
# parameter: self — line 245
# definition: disable — line 251
# parameter: self — line 251
# parameter: subject — line 251
# END CODE MAP

from __future__ import annotations

import base64
import hashlib
import json
import re
import secrets
from dataclasses import dataclass
from typing import Any

import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

ISSUER = "https://identity.example.invalid"
AUDIENCE = "cloud-identity-access-lab"
KID = "ephemeral-fixture-key"
CLAIMS = {
    "iss",
    "aud",
    "sub",
    "iat",
    "nbf",
    "exp",
    "jti",
    "amr",
    "auth_time",
    "token_use",
}


def unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Reject duplicate JSON keys before signature verification so parser ambiguity never chooses privilege."""
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise Rejected("credential_rejected")
        result[key] = value
    return result


class Rejected(ValueError):
    """Constant privacy-safe failure category; never expose supplied tokens, claims or crypto details."""


@dataclass(frozen=True)
class Identity:
    """Verified subject and trusted-time MFA freshness, not client-chosen roles or tenant."""

    subject: str
    mfa_fresh: bool
    expires: int
    fingerprint: str


class FixtureIssuer:
    """Synthetic local issuer only; keys live in process memory and never authenticate real users."""

    def __init__(self) -> None:
        """Generate a fresh standards-library signing key for this isolated fixture lifetime."""
        self._key = Ed25519PrivateKey.generate()

    @property
    def public_key(self) -> Ed25519PublicKey:
        """Expose verification material only, not private signing bytes."""
        return self._key.public_key()

    def issue(
        self, subject: str, now: int, *, mfa: bool = True, **overrides: Any
    ) -> str:
        """Mint controlled test credentials; overrides exist only for signed negative fixture scenarios."""
        claims: dict[str, Any] = {
            "iss": ISSUER,
            "aud": AUDIENCE,
            "sub": subject,
            "iat": now,
            "nbf": now,
            "exp": now + 120,
            "jti": secrets.token_hex(16),
            "amr": ["mfa"] if mfa else ["pwd"],
            "auth_time": now,
            "token_use": "access",
        }
        claims.update(overrides)
        return jwt.encode(
            claims, self._key, algorithm="EdDSA", headers={"kid": KID, "typ": "JWT"}
        )


class Verifier:
    """Pinned issuer/key/algorithm/audience with deterministic authoritative-clock and revocation checks."""

    def __init__(self, key: Ed25519PublicKey) -> None:
        """Keep one trusted public key and bounded in-memory revocation state; no JWKS network resolution."""
        self._key = key
        self._revoked: dict[str, int] = {}
        self._disabled: set[str] = set()
        self._last_now = 0

    def verify(self, token: str, now: int) -> Identity:
        """Verify signature before interpreting claims; reject future/expired/oversized/ambiguous credentials."""
        if type(now) is not int or now < self._last_now or now < 0:
            raise Rejected("clock_rejected")
        self._last_now = now
        if not isinstance(token, str) or len(token) > 4096 or not token.isascii():
            raise Rejected("credential_rejected")
        try:
            segments = token.split(".")
            if len(segments) != 3:
                raise Rejected("credential_rejected")
            for segment in segments[:2]:
                json.loads(
                    base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4)),
                    object_pairs_hook=unique_pairs,
                )
            header = jwt.get_unverified_header(token)
            if header != {"alg": "EdDSA", "kid": KID, "typ": "JWT"}:
                raise Rejected("credential_rejected")
            # Signature, issuer and audience remain verified by PyJWT. All NumericDate
            # bounds are enforced below against the injected trusted clock, never caller claims.
            claims = jwt.decode(
                token,
                self._key,
                algorithms=["EdDSA"],
                issuer=ISSUER,
                audience=AUDIENCE,
                options={
                    "require": sorted(CLAIMS),
                    "strict_aud": True,
                    "verify_exp": False,
                    "verify_iat": False,
                    "verify_nbf": False,
                },
            )
        except (jwt.InvalidTokenError, ValueError, UnicodeError, RecursionError):
            raise Rejected("credential_rejected") from None
        if set(claims) != CLAIMS or claims["token_use"] != "access":
            raise Rejected("credential_rejected")
        if any(
            type(claims[field]) is not int
            for field in ("iat", "nbf", "exp", "auth_time")
        ):
            raise Rejected("credential_rejected")
        if not (
            0 <= claims["auth_time"] <= claims["iat"] <= now < claims["exp"]
            and claims["iat"] <= claims["nbf"] <= now
            and 1 <= claims["exp"] - claims["iat"] <= 300
        ):
            raise Rejected("credential_rejected")
        if not isinstance(claims["sub"], str) or not re.fullmatch(
            r"[A-Za-z0-9:/.@_-]{1,180}", claims["sub"]
        ):
            raise Rejected("credential_rejected")
        if not isinstance(claims["jti"], str) or not re.fullmatch(
            r"[a-f0-9]{32}", claims["jti"]
        ):
            raise Rejected("credential_rejected")
        methods = claims["amr"]
        if (
            not isinstance(methods, list)
            or not 1 <= len(methods) <= 4
            or any(
                type(item) is not str or item not in {"mfa", "pwd", "workload"}
                for item in methods
            )
        ):
            raise Rejected("credential_rejected")
        fingerprint = hashlib.sha256(claims["jti"].encode()).hexdigest()
        self._revoked = {
            key: expiry for key, expiry in self._revoked.items() if expiry > now
        }
        if fingerprint in self._revoked or claims["sub"] in self._disabled:
            raise Rejected("credential_rejected")
        return Identity(
            claims["sub"],
            "mfa" in methods and now - claims["auth_time"] < 300,
            claims["exp"],
            fingerprint,
        )

    def revoke(self, identity: Identity) -> None:
        """Revoke an already-verified credential until expiry; refuse unsafe capacity eviction."""
        if len(self._revoked) >= 256 and identity.fingerprint not in self._revoked:
            raise Rejected("revocation_capacity")
        self._revoked[identity.fingerprint] = identity.expires

    def disable(self, subject: str) -> None:
        """Disable a subject for this fixture lifetime; no re-enable that could resurrect old credentials."""
        if len(self._disabled) >= 256 and subject not in self._disabled:
            raise Rejected("disable_capacity")
        self._disabled.add(subject)
