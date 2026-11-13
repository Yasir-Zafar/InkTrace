import pytest
from hypothesis import given
from hypothesis import strategies as st

from inktrace import zw
from inktrace.payload import BITS, Payload, frame, pack, parse_frames, unpack

payloads = st.builds(
    Payload,
    version=st.just(1),
    doc_id=st.integers(0, 2**32 - 1),
    recipient_id=st.integers(0, 2**16 - 1),
    tag=st.binary(min_size=8, max_size=8),
)

P = Payload(1, 7, 3, bytes(range(8)))


@given(payloads)
def test_pack_roundtrip(p):
    bits = pack(p)
    assert len(bits) == BITS
    assert unpack(bits) == p


@given(payloads)
def test_frame_roundtrip(p):
    assert parse_frames("hi " + frame(p) + "there") == ([p], 0)


def test_frame_len():
    assert len(frame(P)) == 118


@pytest.mark.parametrize(
    "bad",
    [
        Payload(16, 1, 1, bytes(8)),
        Payload(1, 2**32, 1, bytes(8)),
        Payload(1, 1, 2**16, bytes(8)),
        Payload(1, 1, 1, bytes(7)),
    ],
)
def test_pack_rejects(bad):
    with pytest.raises(ValueError):
        pack(bad)


def test_unpack_rejects():
    with pytest.raises(ValueError):
        unpack("0" * 115)
    with pytest.raises(ValueError):
        unpack("2" * 116)
    with pytest.raises(ValueError):
        unpack(pack(Payload(2, 1, 1, bytes(8))))


def test_cut_frame_is_broken():
    f = frame(P)
    assert parse_frames("a " + f[:60]) == ([], 1)
    assert parse_frames(f[60:] + " b") == ([], 1)


def test_inner_mark_is_broken():
    f = frame(P)
    assert parse_frames(f[:50] + zw.MARK + f[50:]) == ([], 1)


def test_several_frames():
    q = Payload(1, 7, 4, bytes(8))
    assert parse_frames(f"a {frame(P)}b c {frame(q)}d") == ([P, q], 0)


def test_no_frames():
    assert parse_frames("just text") == ([], 0)


@given(st.text(alphabet=[zw.ZERO, zw.ONE, zw.MARK, "a", " "]))
def test_fuzz_never_crashes(text):
    found, broken = parse_frames(text)
    assert broken >= 0
    for p in found:
        assert unpack(pack(p)) == p
