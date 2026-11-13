from dataclasses import replace

from inktrace import crypto, zw
from inktrace.payload import Payload, frame
from inktrace.trace import Outcome, explain, trace

KEY = bytes(range(32))
OTHER_KEY = bytes(32)
NAMES = {(7, 1): "alice", (7, 2): "bob"}


def lookup(doc_id, rid):
    return NAMES.get((doc_id, rid))


def mark(doc_id, rid, key=KEY):
    return frame(Payload(1, doc_id, rid, crypto.make_tag(key, 1, doc_id, rid)))


def copy_for(rid, doc_id=7, key=KEY):
    f = mark(doc_id, rid, key)
    return f"The plan {f}is to meet at noon. Do not {f}share this with {f}anyone."


def test_traced_full_copy():
    r = trace(copy_for(1), KEY, lookup)
    assert r.outcome is Outcome.TRACED
    assert r.hits[0].name == "alice" and r.valid == 3
    assert "alice" in explain(r)


def test_partial_copy_one_frame():
    text = copy_for(2)
    part = text[text.index("Do not") :]
    r = trace(part, KEY, lookup)
    assert r.outcome is Outcome.TRACED and r.hits[0].name == "bob"


def test_partial_copy_only_cut_frame():
    f = mark(7, 1)
    r = trace("noon. " + f[:40], KEY, lookup)
    assert r.outcome is Outcome.TAMPERED and r.hits == [] and r.broken == 1


def test_not_found():
    r = trace(zw.strip_zero_width(copy_for(1)), KEY, lookup)
    assert r.outcome is Outcome.NOT_FOUND
    assert explain(r) == "No watermark found."


def test_bit_flip_never_accuses():
    f = mark(7, 1)
    bits = zw.zw_to_bits(f[1:-1])
    for i in range(len(bits)):
        flipped = bits[:i] + ("1" if bits[i] == "0" else "0") + bits[i + 1 :]
        r = trace("x " + zw.MARK + zw.bits_to_zw(flipped) + zw.MARK, KEY, lookup)
        assert r.hits == [], i
        assert r.outcome is Outcome.TAMPERED


def test_insider_swaps_recipient_id():
    # alice rewrites her code to point at bob, keeping her own tag
    tag = crypto.make_tag(KEY, 1, 7, 1)
    forged = frame(Payload(1, 7, 2, tag))
    r = trace("x " + forged, KEY, lookup)
    assert r.outcome is Outcome.TAMPERED and r.invalid == 1
    assert "Nobody named" in explain(r)


def test_wrong_key_never_accuses():
    r = trace(copy_for(1, key=OTHER_KEY), KEY, lookup)
    assert r.outcome is Outcome.TAMPERED and r.invalid == 3


def test_transplant_from_other_doc():
    # a valid frame from doc 8 is still valid, but points at doc 8, not doc 7
    r = trace(copy_for(1, doc_id=8), KEY, lookup)
    assert r.outcome is Outcome.UNREGISTERED
    assert r.hits[0].doc_id == 8
    assert "not in the database" in explain(r)


def test_collusion_merged_copies():
    a, b = copy_for(1), copy_for(2)
    merged = a[: len(a) // 2] + b[len(b) // 2 :]
    r = trace(merged, KEY, lookup)
    assert r.outcome is Outcome.COLLUSION
    assert {h.name for h in r.hits} == {"alice", "bob"}
    assert "collusion" in explain(r)


def test_valid_plus_forged_reports_both():
    forged = frame(replace(Payload(1, 7, 2, bytes(8))))
    r = trace(copy_for(1) + " " + forged, KEY, lookup)
    assert r.outcome is Outcome.TRACED and r.invalid == 1
    assert "Ignored: 1" in explain(r)
