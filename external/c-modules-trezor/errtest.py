#!/usr/bin/env python3
"""
Exception-type parity between the libngu-backed and trezor-crypto-backed builds.

shared/ catches specific exception classes around ngu calls, so a changed type
is a real incompatibility even when the failure condition itself matches. This
compares only the class name (and whether it raised at all), not the message.

  python3 external/c-modules-trezor/errtest.py
"""
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MPY_DIR = ROOT / "external/micropython/ports/unix"
LIBNGU = MPY_DIR / "coldcard-mpy"
TREZOR = MPY_DIR / "coldcard-mpy-tz"

# Bad / edge inputs. Each should raise the SAME class on both builds (or neither).
CASES = [
    # hash
    'ngu.hash.ripemd160(b"a"*64)',            # libngu caps at 63
    'ngu.hash.sha256t(b"tag", b"msg", True)',  # pre-hashed tag, wrong length
    'ngu.hash.pbkdf2_sha512(b"pw", b"", 100)', # empty salt
    'ngu.hash.pbkdf2_sha512(b"pw", b"salt", 0)',  # zero rounds
    'ngu.hash.sha256s()',                      # missing arg
    'ngu.hash.sha256s(123)',                   # not a buffer
    # random
    'ngu.random.bytes(4097)',                  # over cap
    'ngu.random.bytes(-1)',
    'ngu.random.uniform(0)',
    # libngu asserts bit_length(mx) < 31, so a bound at/above 2**30 raises
    # AssertionError there and returns a value here. Not reachable: the largest
    # bound any caller passes is multisig.py's 1<<28.
    'ngu.random.uniform(1<<30)',
    # reseed() takes an int in libngu (yasmarang_pad = get_int_truncated) and so
    # rejects other types. The trezor backend's reseed is a deliberate no-op --
    # but a no-op that also dropped libngu's ARGUMENT CHECKING, which is not part
    # of that decision. shared/mk4.py:rng_seeding() is the only caller.
    'ngu.random.reseed(None)',
    'ngu.random.reseed("x")',
    'ngu.random.reseed([1])',
    'ngu.random.reseed(1)',                    # valid: must be accepted by both
    # codecs
    'ngu.codecs.b58_decode("notbase58!!!")',
    'ngu.codecs.b58_decode("")',
    'ngu.codecs.b58_decode("1" * 200)',
    'ngu.codecs.b32_decode("!!!!")',
    'ngu.codecs.b32_decode("A")',              # invalid base32 length
    'ngu.codecs.b32_decode("MZXW\\x006YTBOI")',  # embedded NUL: libngu truncates
    'ngu.codecs.b32_decode("A\\x00B")',
    'ngu.codecs.b32_decode("\\x00MZXW6YTBOI")',  # leading NUL: libngu -> b""
    'ngu.codecs.b32_decode("MZXW6YTBOI\\x00")',  # trailing NUL: libngu decodes it all
    'ngu.codecs.b58_encode(b"x" * 200)',       # over 128-byte working buffer
    'ngu.codecs.segwit_decode("notanaddress")',
    'ngu.codecs.segwit_decode("bc1qqqqqqq")',  # bad checksum
    'ngu.codecs.segwit_decode("bc1" + "q"*200)',  # overlong, bounds check
    'ngu.codecs.segwit_encode("bc", 0, b"\\x00"*5)',   # bad program length
    'ngu.codecs.segwit_encode("x"*60, 0, b"\\x00"*20)',  # overlong hrp
    # hdnode -- invalid node access must raise, not crash
    'ngu.hdnode.HDNode().privkey()',
    'ngu.hdnode.HDNode().pubkey()',
    'ngu.hdnode.HDNode().depth()',
    'ngu.hdnode.HDNode().serialize(0, True)',
    'ngu.hdnode.HDNode().derive(0, False)',
    'ngu.hdnode.HDNode().copy()',
    'ngu.hdnode.HDNode().from_chaincode_privkey(b"\\x00"*31, b"\\x01"*32)',
    'ngu.hdnode.HDNode().from_chaincode_privkey(b"\\x00"*32, b"\\x01"*31)',
    'ngu.hdnode.HDNode().from_chaincode_pubkey(b"\\x00"*32, b"\\xff"*33)',
    'ngu.hdnode.HDNode().deserialize("garbage")',
    'ngu.hdnode.HDNode().deserialize("")',
    # blanked node must not be usable
    '(lambda n: (n.blank(), n.privkey()))'
    '(ngu.hdnode.HDNode().from_master(b"\\x00"*32))',
    # ambiguous index: bit 31 set but hard=False. The two backends resolve this
    # to DIFFERENT private keys, so this backend refuses it outright.
    'ngu.hdnode.HDNode().from_master(b"\\x00"*32).derive(0x80000000, False)',
    # hardened derive on a public-only node
    '(lambda n: n.derive(0, True))(ngu.hdnode.HDNode().from_chaincode_pubkey('
    'b"\\x00"*32, ngu.secp256k1.keypair(b"\\x01"*32).pubkey().to_bytes()))',
    # secp256k1
    'ngu.secp256k1.keypair(b"\\x00"*32)',      # zero privkey, invalid scalar
    'ngu.secp256k1.keypair(b"\\xff"*32)',      # above group order
    'ngu.secp256k1.keypair(b"\\x01"*31)',      # wrong length
    'ngu.secp256k1.pubkey(b"\\x02"*10)',       # truncated pubkey -> over-read risk
    'ngu.secp256k1.pubkey(b"")',
    'ngu.secp256k1.pubkey(b"\\x09"*33)',       # bad prefix byte
    'ngu.secp256k1.signature(b"\\x00"*64)',    # wrong length (needs 65)
    'ngu.secp256k1.signature(b"\\x00"*65)',    # all-zero sig
    'ngu.secp256k1.sign(b"\\x01"*32, b"\\x00"*31, 0)',   # short digest
    'ngu.secp256k1.sign(b"\\x01"*31, b"\\x00"*32, 0)',   # short privkey
    # aes
    'ngu.aes.CTR(b"\\x00"*15)',                # bad key length
    'ngu.aes.CTR(b"\\x00"*32, b"\\x01"*15)',   # bad nonce length
    'ngu.aes.CBC(True, b"\\x00"*32, b"\\x00"*15)',   # bad iv
    'ngu.aes.CBC(True, b"\\x00"*32)',          # missing iv (CBC needs 3 args)
    'ngu.aes.CBC(True, b"\\x00"*32, b"\\x00"*16).cipher(b"short")',  # not %16
]

# Divergences that are deliberate. Anything NOT in here is a bug.
#
# Keyed by the FULL expression, and stating the exact outcome expected from
# EACH backend -- not just a reason. The previous version keyed on a substring
# and recorded only prose, which meant an allowlisted case still passed if the
# two backends silently converged, or if BOTH changed to some entirely new pair
# of outcomes. An allowlist that cannot fail is not evidence.
#
# "CRASH" matches any CRASH(rc=N): the signal number for a SIGBUS differs
# between macOS and the Linux CI runner, and that is not what is being asserted.
EXPECTED_DIVERGENCES = {
    # libngu SIGBUSes on a negative count; we raise ValueError.
    'ngu.random.bytes(-1)': (
        "CRASH", "ValueError",
        "libngu crashes (SIGBUS) on negative count"),
    # libngu's decoder loop is `while (*ptr)`, so it stops at an embedded NUL
    # and silently returns a TRUNCATED result -- e.g. b'fo' for a 6-byte
    # secret. These decode TOTP secrets (users.py) and QR payloads (bbqr.py),
    # where silently shortening secret material is worse than refusing it.
    'ngu.codecs.b32_decode("MZXW\\x006YTBOI")': (
        "no-raise", "ValueError",
        "libngu silently truncates at an embedded NUL"),
    'ngu.codecs.b32_decode("A\\x00B")': (
        "no-raise", "ValueError",
        "libngu silently truncates at an embedded NUL"),
    'ngu.codecs.b32_decode("\\x00MZXW6YTBOI")': (
        "no-raise", "ValueError",
        "libngu truncates to b'' at a LEADING NUL"),
    # The one NUL position where libngu is not lossy -- it stops at the NUL
    # having already consumed every real character, so it returns the FULL
    # value. The shim still refuses, because it scans all slen bytes. Kept
    # strict: "reject NUL in base32" is easier to reason about than "reject it
    # unless it happens to be last".
    'ngu.codecs.b32_decode("MZXW6YTBOI\\x00")': (
        "no-raise", "ValueError",
        "trailing NUL: libngu decodes fully (not truncated); we still refuse"),
    # See the DIVERGENCE comment in mod_hdnode_tz.c s_hdnode_derive().
    'ngu.hdnode.HDNode().from_master(b"\\x00"*32).derive(0x80000000, False)': (
        "no-raise", "ValueError",
        "ambiguous hardened bit: backends produce DIFFERENT keys; we refuse"),
    # --- known, NOT yet fixed. These are findings, recorded so they cannot
    # --- drift silently; they are not decisions. See TREZOR-CRYPTO-BACKEND.md.
    'ngu.random.uniform(1<<30)': (
        "AssertionError", "no-raise",
        "libngu asserts bit_length(mx) < 31; unreached (max caller bound 1<<28)"),
    'ngu.random.reseed(None)': (
        "TypeError", "no-raise",
        "shim's reseed no-op also dropped libngu's argument type check"),
    'ngu.random.reseed("x")': (
        "TypeError", "no-raise",
        "shim's reseed no-op also dropped libngu's argument type check"),
    'ngu.random.reseed([1])': (
        "TypeError", "no-raise",
        "shim's reseed no-op also dropped libngu's argument type check"),
}


def expected(expr, a, b):
    """Return (matched, why). matched is False if the pair is not the one recorded."""
    ent = EXPECTED_DIVERGENCES.get(expr)
    if ent is None:
        return False, None
    want_a, want_b, why = ent
    ok_a = a.startswith("CRASH") if want_a == "CRASH" else a == want_a
    ok_b = b.startswith("CRASH") if want_b == "CRASH" else b == want_b
    if ok_a and ok_b:
        return True, why
    return False, ("expected libngu=%s trezor=%s, got libngu=%s trezor=%s"
                   % (want_a, want_b, a, b))


WRAPPER = """import ngu
try:
    _r = %s
    print("no-raise")
except Exception as e:
    print(type(e).__name__)
"""


def run(binary, expr):
    try:
        r = subprocess.run([str(binary), "-c", WRAPPER % expr],
                           capture_output=True, timeout=60, text=True)
    except subprocess.TimeoutExpired:
        return "TIMEOUT"
    out = r.stdout.strip()
    if r.returncode != 0 and not out:
        # crashed hard rather than raising -- that is itself the finding
        return "CRASH(rc=%d)" % r.returncode
    return out or "NO-OUTPUT"


def main():
    for b in (LIBNGU, TREZOR):
        if not b.exists():
            print("missing binary: %s" % b)
            return 2

    same = differ = intended = 0
    fired = set()
    for expr in CASES:
        a = run(LIBNGU, expr)
        b = run(TREZOR, expr)
        short = expr if len(expr) < 60 else expr[:57] + "..."
        flag = "CRASH" in a or "CRASH" in b
        if a == b and not flag:
            same += 1
            print("  ok      %-60s both -> %s" % (short, a))
        else:
            ok, why = expected(expr, a, b)
            if ok:
                intended += 1
                fired.add(expr)
                print("  ok*     %-60s libngu=%s trezor=%s" % (short, a, b))
                print("          ^ intended: %s" % why)
            else:
                differ += 1
                print("  DIFFER  %-60s libngu=%s trezor=%s" % (short, a, b))
                if why:
                    print("          ^ %s" % why)

    total = same + intended + differ
    print("\n%d matching, %d intended divergences, %d UNEXPECTED"
          % (same, intended, differ))
    # Floor: a harness that compares nothing must not report success.
    if total != len(CASES):
        print("FATAL: only %d of %d cases produced a comparison" % (total, len(CASES)))
        return 2
    # Every recorded divergence must actually occur. One that stops happening is
    # as much a change in behaviour as a new one appearing -- and it would
    # otherwise sit in this file forever describing something that is no longer
    # true. (This is what catches a divergence being fixed but not documented.)
    stale = sorted(set(EXPECTED_DIVERGENCES) - fired)
    if stale:
        print("FATAL: %d allowlisted divergence(s) did not occur:" % len(stale))
        for k in stale:
            print("  %s" % k)
        print("  Either the backends now agree (delete the entry) or the case "
              "was renamed (the key must be the FULL expression).")
        return 2
    if differ:
        print("FAIL: unexpected divergence from libngu")
    return 1 if differ else 0


if __name__ == "__main__":
    sys.exit(main())
