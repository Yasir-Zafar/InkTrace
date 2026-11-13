"""Keys and HMAC tags.

K_doc = HMAC-SHA256(K, "inktrace-doc" || doc_id)
tag   = HMAC-SHA256(K_doc, "inktrace-v1" || version || doc_id || recipient_id)[:8]
"""

import hashlib
import hmac
import secrets
import struct

KEY_LEN = 32
TAG_LEN = 8


def generate_key() -> bytes:
    return secrets.token_bytes(KEY_LEN)


def derive_doc_key(key: bytes, doc_id: int) -> bytes:
    return hmac.new(key, b"inktrace-doc" + struct.pack(">I", doc_id), hashlib.sha256).digest()


def make_tag(key: bytes, version: int, doc_id: int, recipient_id: int) -> bytes:
    msg = b"inktrace-v1" + struct.pack(">BIH", version, doc_id, recipient_id)
    doc_key = derive_doc_key(key, doc_id)
    return hmac.new(doc_key, msg, hashlib.sha256).digest()[:TAG_LEN]


def verify_tag(key: bytes, version: int, doc_id: int, recipient_id: int, tag: bytes) -> bool:
    return hmac.compare_digest(make_tag(key, version, doc_id, recipient_id), tag)


def key_to_hex(key: bytes) -> str:
    return key.hex()


def load_key(path: str | None = None) -> bytes:
    """Load a hex key from a file, or from INKTRACE_KEY if no path is given."""
    import os

    if path:
        with open(path) as f:
            raw = f.read().strip()
    else:
        raw = os.environ.get("INKTRACE_KEY", "").strip()
        if not raw:
            raise ValueError("no key: pass a key file or set INKTRACE_KEY")
    try:
        key = bytes.fromhex(raw)
    except ValueError:
        raise ValueError("key must be hex") from None
    if len(key) != KEY_LEN:
        raise ValueError(f"key must be {KEY_LEN} bytes")
    return key


def save_key(key: bytes, path: str) -> None:
    """Write a hex key readable only by the owner."""
    import os

    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(key_to_hex(key) + "\n")
