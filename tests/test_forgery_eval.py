import random
import runpy
from pathlib import Path

from inktrace import crypto

forgery = runpy.run_path(str(Path(__file__).parent.parent / "eval" / "forgery.py"))


def test_small_run_has_no_false_accusations():
    key = crypto.generate_key()
    assert forgery["random_frames"](key, 2000, random.Random(1)) == 0
    tries, hits = forgery["insider_swap"](key)
    assert tries == 50 * 49 and hits == 0
    tries, hits = forgery["bit_flips"](key)
    assert tries == 50 * 116 and hits == 0
