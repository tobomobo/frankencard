#!/usr/bin/env python3
"""
Differentially fuzz ngu.codecs.b32_decode against libngu.

Why this exists: the base32 decoder in mod_codecs_tz.c is hand-written, because
libngu's is deliberately lenient (it skips whitespace and dashes and remaps the
mistyped '0'->O, '1'->L, '8'->B) and shared/teleport.py depends on that for
hand-typed Teleport Passwords. A hand-rolled parser of attacker-supplied input
deserves more than a handful of vectors, so this throws a few hundred adversarial
strings at both interpreters and demands identical results -- values AND
exception types.

It found one real divergence: libngu's decode loop is `while (... && *ptr)`, so
an embedded NUL silently TRUNCATES the result rather than being rejected. That is
listed in EXPECTED below; anything else is a bug.

  python3 external/c-modules-trezor/fuzz_codecs.py

Deterministic (fixed seed), so a failure is always reproducible.
"""
import random
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MPY = ROOT / "external/micropython/ports/unix"
LIBNGU, TREZOR = MPY / "coldcard-mpy", MPY / "coldcard-mpy-tz"

B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
LENIENT = " \t\r\n-"            # libngu skips these
CONFUSED = "018"                # libngu remaps these to O, L, B
JUNK = "!@#$%^&*()_+=[]{};:'\",.<>/?\\|`~089"

# Inputs where a difference is intentional. See errtest.py for the full rationale.
EXPECTED = ("\x00",)            # libngu truncates at an embedded NUL

random.seed(1337)


def corpus():
    out = []
    for n in range(49):                      # valid base32, every length
        out.append("".join(random.choice(B32) for _ in range(n)))
    for _ in range(120):                     # leniency characters mixed in
        out.append("".join(random.choice(B32 + LENIENT + CONFUSED)
                           for _ in range(random.randint(0, 24))))
    for _ in range(120):                     # junk: must be rejected identically
        out.append("".join(random.choice(B32 + JUNK)
                           for _ in range(random.randint(1, 20))))
    for _ in range(60):                      # '=' in legal and illegal places
        s = "".join(random.choice(B32) for _ in range(random.randint(0, 16)))
        pos = random.randint(0, len(s))
        out.append(s[:pos] + "=" * random.randint(1, 3) + s[pos:])
    for _ in range(60):                      # mixed case
        out.append("".join(random.choice(B32 + B32.lower())
                           for _ in range(random.randint(0, 20))))
    out += ["", "=", "===", "-", " ", "\t\n", "0", "1", "8", "018", "O", "L", "B",
            "A" * 200, "-" * 50, "A-B C\tD\nE", "aA2-7=", "MZXW6YTBOI"]
    return out


# Every line is prefixed, so an empty decode is still a line. Do NOT strip the
# output: an earlier version of this script used .strip().split() and silently
# dropped leading/trailing empty results, hiding 8 inputs per run.
PROG = """
import ngu
from ubinascii import hexlify as H
for s in %r:
    try:
        print("OK:" + H(ngu.codecs.b32_decode(s)).decode())
    except Exception as e:
        print("E:" + type(e).__name__)
"""


def run(binary, batch):
    r = subprocess.run([str(binary), "-c", PROG % batch],
                       capture_output=True, text=True, timeout=120)
    if r.returncode != 0:
        return None
    return [l for l in r.stdout.split("\n") if l[:3] in ("OK:", "E:_") or l[:2] == "E:"]


def main():
    for b in (LIBNGU, TREZOR):
        if not b.exists():
            print("missing binary: %s -- build both backends first" % b)
            return 2

    cases = corpus()
    print("fuzzing b32_decode: %d inputs, both backends" % len(cases))

    BATCH, bad, intended, checked = 50, 0, 0, 0
    for i in range(0, len(cases), BATCH):
        batch = cases[i:i + BATCH]
        a, b = run(LIBNGU, batch), run(TREZOR, batch)

        if a is None or b is None:
            print("  CRASH in batch %d: libngu=%s trezor=%s"
                  % (i, a is None, b is None))
            bad += 1
            continue
        if len(a) != len(batch) or len(b) != len(batch):
            print("  HARNESS ERROR batch %d: inputs=%d libngu=%d trezor=%d"
                  % (i, len(batch), len(a), len(b)))
            bad += 1
            continue

        for s, x, y in zip(batch, a, b):
            checked += 1
            if x == y:
                continue
            if any(e in s for e in EXPECTED):
                intended += 1
                continue
            bad += 1
            print("  MISMATCH %r\n    libngu=%s\n    trezor=%s" % (s, x, y))

    print("\n%d inputs compared, %d intended divergences, %d problems"
          % (checked, intended, bad))
    if checked != len(cases):
        print("FAIL: only %d of %d inputs were actually compared"
              % (checked, len(cases)))
        return 1
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
