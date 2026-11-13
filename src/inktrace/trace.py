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
