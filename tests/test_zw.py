import pytest
from hypothesis import given
from hypothesis import strategies as st

from inktrace import zw

bitstrings = st.text(alphabet="01", max_size=300)


@given(bitstrings)
def test_roundtrip(bits):
    assert zw.zw_to_bits(zw.bits_to_zw(bits)) == bits


@given(bitstrings)
def test_encoded_is_invisible(bits):
    assert zw.strip_zero_width(zw.bits_to_zw(bits)) == ""


def test_bad_bits():
    with pytest.raises(ValueError):
        zw.bits_to_zw("012")


def test_bad_chars():
    with pytest.raises(ValueError):
        zw.zw_to_bits(zw.ZERO + "a")
    with pytest.raises(ValueError):
        zw.zw_to_bits(zw.MARK)


@given(st.text())
def test_strip_keeps_normal_text(text):
    clean = zw.strip_zero_width(text)
    assert not zw.has_zero_width(clean)
    assert zw.strip_zero_width(clean) == clean


def test_strip_and_reveal():
    text = "a" + zw.ZERO + "b" + zw.MARK + "c\ufeff"
    assert zw.strip_zero_width(text) == "abc"
    assert zw.reveal(text) == "a<ZWSP>b<WJ>c<BOM>"
    assert zw.has_zero_width(text)
    assert not zw.has_zero_width("plain")
