"""Zero-width character codec.

Bits are written one per character: U+200B is 0, U+200C is 1.
U+2060 (word joiner) marks the start and end of a frame.
"""

import re

ZERO = "\u200b"
ONE = "\u200c"
MARK = "\u2060"

# Every invisible character we know of, including ones we never write.
# Used for stripping and for revealing hidden text.
NAMES = {
    "\u200b": "ZWSP",
    "\u200c": "ZWNJ",
    "\u200d": "ZWJ",
    "\u200e": "LRM",
    "\u200f": "RLM",
    "\u2060": "WJ",
    "\u2061": "FA",
    "\u2062": "IT",
    "\u2063": "IS",
    "\u2064": "IP",
    "\ufeff": "BOM",
}

ZW_RE = re.compile("[" + "".join(NAMES) + "]")


def bits_to_zw(bits: str) -> str:
    """Turn a string of '0'/'1' into zero-width characters."""
    if not set(bits) <= {"0", "1"}:
        raise ValueError("bits must only contain 0 and 1")
    return bits.replace("0", ZERO).replace("1", ONE)


def zw_to_bits(chars: str) -> str:
    """Turn zero-width data characters back into a '0'/'1' string."""
    if not set(chars) <= {ZERO, ONE}:
        raise ValueError("not zero-width data characters")
    return chars.replace(ZERO, "0").replace(ONE, "1")


def strip_zero_width(text: str) -> str:
    """Remove every zero-width character."""
    return ZW_RE.sub("", text)


def has_zero_width(text: str) -> bool:
    return ZW_RE.search(text) is not None


def reveal(text: str) -> str:
    """Show hidden characters as <NAME> so a person can see them."""
    return ZW_RE.sub(lambda m: f"<{NAMES[m.group()]}>", text)
