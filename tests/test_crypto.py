import hashlib
import hmac
import os
import stat

import pytest
from hypothesis import given
from hypothesis import strategies as st

from inktrace import crypto

KEY = bytes(range(32))


def test_rfc4231_case_2():
    # Shows the stdlib HMAC-SHA256 we build on matches the RFC 4231 test vector.
    mac = hmac.new(b"Jefe", b"what do ya want for nothing?", hashlib.sha256).hexdigest()
    assert mac == "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"


def test_generate_key():
    a, b = crypto.generate_key(), crypto.generate_key()
    assert len(a) == 32 and a != b


def test_tag_len_and_stable():
    t = crypto.make_tag(KEY, 1, 7, 3)
    assert len(t) == 8
    assert t == crypto.make_tag(KEY, 1, 7, 3)


def test_tag_depends_on_every_input():
    base = crypto.make_tag(KEY, 1, 7, 3)
    assert base != crypto.make_tag(KEY, 2, 7, 3)
    assert base != crypto.make_tag(KEY, 1, 8, 3)
    assert base != crypto.make_tag(KEY, 1, 7, 4)
    assert base != crypto.make_tag(bytes(32), 1, 7, 3)


def test_doc_keys_differ():
    assert crypto.derive_doc_key(KEY, 1) != crypto.derive_doc_key(KEY, 2)


@given(st.integers(0, 63))
def test_any_bit_flip_fails(bit):
    tag = bytearray(crypto.make_tag(KEY, 1, 7, 3))
    tag[bit // 8] ^= 1 << (bit % 8)
    assert not crypto.verify_tag(KEY, 1, 7, 3, bytes(tag))


def test_verify_ok():
    tag = crypto.make_tag(KEY, 1, 7, 3)
    assert crypto.verify_tag(KEY, 1, 7, 3, tag)
    assert not crypto.verify_tag(KEY, 1, 7, 4, tag)


def test_save_and_load(tmp_path):
    path = tmp_path / "k.hex"
    crypto.save_key(KEY, str(path))
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    assert crypto.load_key(str(path)) == KEY
    with pytest.raises(FileExistsError):
        crypto.save_key(KEY, str(path))


def test_load_from_env(monkeypatch):
    monkeypatch.setenv("INKTRACE_KEY", KEY.hex())
    assert crypto.load_key() == KEY
    monkeypatch.delenv("INKTRACE_KEY")
    with pytest.raises(ValueError):
        crypto.load_key()


@pytest.mark.parametrize("raw", ["zz", "ab" * 16])
def test_load_bad_key(tmp_path, raw):
    path = tmp_path / "k.hex"
    path.write_text(raw)
    with pytest.raises(ValueError):
        crypto.load_key(str(path))
