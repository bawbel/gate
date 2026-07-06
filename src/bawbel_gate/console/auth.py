"""Bearer token minting and constant-time verification for the console API.

See DESIGN.md 13.1 -- token is minted once at startup and printed to stdout.
The token is a random hex string; verification uses hmac.compare_digest to
resist timing side-channels.
"""

from __future__ import annotations

import hmac
import secrets

TOKEN_BYTE_LENGTH = 32  # 256-bit token -> 64-char hex string


def mint_token() -> str:
    """Return a cryptographically random bearer token (hex-encoded)."""
    return secrets.token_hex(TOKEN_BYTE_LENGTH)


def verify_token(provided: str, expected: str) -> bool:
    """Return True iff provided == expected, using constant-time comparison."""
    if not provided or not expected:
        return False
    return hmac.compare_digest(provided.encode(), expected.encode())
