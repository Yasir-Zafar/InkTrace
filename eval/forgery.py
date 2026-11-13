"""Forgery and false-accusation experiment.

Tries to make InkTrace name an innocent recipient without the key.
Writes eval/results/forgery.json.

Run: python eval/forgery.py [--n 1000000]
"""

import argparse
import json
import random
import time
from pathlib import Path

from inktrace import crypto, zw
from inktrace.payload import Payload, frame
from inktrace.trace import trace

DOC = 7
RECIPIENTS = {rid: f"r{rid}" for rid in range(1, 51)}
BATCH = 1000


def lookup(doc_id, rid):
    return RECIPIENTS.get(rid) if doc_id == DOC else None


def accused(text, key):
    return trace(text, key, lookup).valid


def random_frames(key, n, rng):
    """Random tags on real (doc, recipient) pairs: an attacker guessing tags."""
    hits = 0
    rids = list(RECIPIENTS)
    for start in range(0, n, BATCH):
        frames = [
            frame(Payload(1, DOC, rng.choice(rids), rng.randbytes(8)))
            for _ in range(min(BATCH, n - start))
        ]
        hits += accused(" ".join(frames), key)
    return hits


def insider_swap(key):
    """Every recipient rewrites their id to every other recipient's id."""
    tries = hits = 0
    for own in RECIPIENTS:
        tag = crypto.make_tag(key, 1, DOC, own)
        for other in RECIPIENTS:
            if other != own:
                tries += 1
                hits += accused(frame(Payload(1, DOC, other, tag)), key)
    return tries, hits


def bit_flips(key):
    """Every single-bit flip of every recipient's frame."""
    tries = hits = 0
    for rid in RECIPIENTS:
        f = frame(Payload(1, DOC, rid, crypto.make_tag(key, 1, DOC, rid)))
        bits = zw.zw_to_bits(f[1:-1])
        for i in range(len(bits)):
            flipped = bits[:i] + str(1 - int(bits[i])) + bits[i + 1 :]
            tries += 1
            hits += accused(zw.MARK + zw.bits_to_zw(flipped) + zw.MARK, key)
    return tries, hits


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=1_000_000)
    ap.add_argument("--seed", type=int, default=2026)
    ap.add_argument("--out", default="eval/results/forgery.json")
    args = ap.parse_args()

    rng = random.Random(args.seed)  # noqa: S311 (attacker simulation, not crypto)
    key = crypto.generate_key()

    t0 = time.perf_counter()
    random_hits = random_frames(key, args.n, rng)
    swap_tries, swap_hits = insider_swap(key)
    flip_tries, flip_hits = bit_flips(key)
    secs = time.perf_counter() - t0

    result = {
        "recipients": len(RECIPIENTS),
        "random_tag_guesses": args.n,
        "random_tag_false_accusations": random_hits,
        "insider_swap_tries": swap_tries,
        "insider_swap_false_accusations": swap_hits,
        "bit_flip_tries": flip_tries,
        "bit_flip_false_accusations": flip_hits,
        "theory_success_per_guess": "2^-64",
        "theory_expected_hits_random": args.n / 2**64,
        "seconds": round(secs, 1),
    }
    Path(args.out).write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
