"""Find and verify frames in a leaked text.

Only a frame with a valid HMAC tag can name a recipient. Everything else is
counted and reported, never used to blame anyone.
"""

from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum

from inktrace import crypto
from inktrace.payload import parse_frames

Lookup = Callable[[int, int], str | None]


class Outcome(str, Enum):
    TRACED = "traced"
    COLLUSION = "collusion"
    TAMPERED = "tampered"
    UNREGISTERED = "unregistered"
    NOT_FOUND = "not_found"


@dataclass(frozen=True)
class Hit:
    doc_id: int
    recipient_id: int
    name: str | None
    frames: int


@dataclass
class TraceResult:
    outcome: Outcome
    hits: list[Hit] = field(default_factory=list)
    invalid: int = 0
    broken: int = 0

    @property
    def valid(self) -> int:
        return sum(h.frames for h in self.hits)


def trace(text: str, key: bytes, lookup: Lookup) -> TraceResult:
    """Trace a leaked text. lookup(doc_id, recipient_id) returns a name or None."""
    payloads, broken = parse_frames(text)
    counts: Counter[tuple[int, int]] = Counter()
    invalid = 0
    for p in payloads:
        if crypto.verify_tag(key, p.version, p.doc_id, p.recipient_id, p.tag):
            counts[(p.doc_id, p.recipient_id)] += 1
        else:
            invalid += 1

    if not counts:
        outcome = Outcome.TAMPERED if payloads or broken else Outcome.NOT_FOUND
        return TraceResult(outcome, invalid=invalid, broken=broken)

    hits = [Hit(d, r, lookup(d, r), n) for (d, r), n in counts.most_common()]
    if len(hits) > 1:
        outcome = Outcome.COLLUSION
    elif hits[0].name is None:
        outcome = Outcome.UNREGISTERED
    else:
        outcome = Outcome.TRACED
    return TraceResult(outcome, hits, invalid, broken)


def explain(r: TraceResult) -> str:
    """Human readable report for the CLI and web page."""
    def who(h: Hit) -> str:
        name = h.name or "unknown recipient"
        return f"{name} (doc {h.doc_id}, recipient {h.recipient_id}, {h.frames} valid)"

    lines = {
        Outcome.TRACED: f"Leaked by: {who(r.hits[0])}" if r.hits else "",
        Outcome.COLLUSION: "Several valid recipients, possible collusion:",
        Outcome.TAMPERED: "Possible tampering: hidden codes found but none are valid. Nobody named.",
        Outcome.UNREGISTERED: f"Valid code but not in the database: {who(r.hits[0])}"
        if r.hits
        else "",
        Outcome.NOT_FOUND: "No watermark found.",
    }
    out = [lines[r.outcome]]
    if r.outcome is Outcome.COLLUSION:
        out += [f"  - {who(h)}" for h in r.hits]
    if r.invalid or r.broken:
        out.append(f"Ignored: {r.invalid} frame(s) with bad tags, {r.broken} damaged frame(s).")
    return "\n".join(out)
