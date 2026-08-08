#!/usr/bin/env python3
"""
Differential test: run identical `ngu` expressions on the libngu-backed and the
trezor-crypto-backed micropython builds and require byte-identical results.

Only deterministic functions are compared. RNG is checked separately.

  python3 external/c-modules-trezor/difftest.py
"""
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MPY_DIR = ROOT / "external/micropython/ports/unix"
LIBNGU = MPY_DIR / "coldcard-mpy"
TREZOR = MPY_DIR / "coldcard-mpy-tz"

# Each case is an expression evaluated with `ngu` imported and H = hexlify.
CASES = [
    # --- hash ---
    'H(ngu.hash.sha256s(b""))',
    'H(ngu.hash.sha256s(b"abc"))',
    'H(ngu.hash.sha256s(b"x"*1000))',
    'H(ngu.hash.sha256d(b""))',
    'H(ngu.hash.sha256d(b"hello world"))',
    'H(ngu.hash.sha256t(b"TapLeaf", b"abc"))',
    'H(ngu.hash.sha256t(b"BIP0340/challenge", b""))',
    'H(ngu.hash.sha256t(ngu.hash.sha256s(b"TapSighash"), b"msg", True))',
    'H(ngu.hash.ripemd160(b""))',
    'H(ngu.hash.ripemd160(b"abc"))',
    'H(ngu.hash.ripemd160(b"a"*63))',
    'H(ngu.hash.hash160(b""))',
    'H(ngu.hash.hash160(b"\\x02"*33))',
    'H(ngu.hash.pbkdf2_sha512(b"password", b"salt", 1))',
    'H(ngu.hash.pbkdf2_sha512(b"mnemonic", b"TREZOR", 2048))',
    'H(ngu.hash.sha512(b"abc").digest())',
    'H(ngu.hash.sha512().digest())',
    # incremental sha512 must match one-shot
    '(lambda o: (o.update(b"ab"), o.update(b"c"), H(o.digest()))[-1])(ngu.hash.sha512())',
    # --- hmac ---
    'H(ngu.hmac.hmac_sha256(b"key", b"The quick brown fox"))',
    'H(ngu.hmac.hmac_sha256(b"k"*100, b"long key gets hashed"))',
    'H(ngu.hmac.hmac_sha512(b"Bitcoin seed", b"\\x00"*32))',
    'H(ngu.hmac.hmac_sha512(b"", b""))',
    'H(ngu.hmac.hmac_sha1(b"key", b"totp"))',
    'H(ngu.hmac.hmac_sha1(b"k"*100, b"long key"))',
    'H(ngu.hmac.hmac_sha1(b"", b""))',
    # --- codecs ---
    'ngu.codecs.b58_encode(b"\\x00"*21)',
    'ngu.codecs.b58_encode(bytes(range(21)))',
    'H(ngu.codecs.b58_decode(ngu.codecs.b58_encode(bytes(range(21)))))',
    'ngu.codecs.b32_encode(b"foobar")',
    'ngu.codecs.b32_encode(b"")',
    'H(ngu.codecs.b32_decode(ngu.codecs.b32_encode(b"foobar")))',
    'ngu.codecs.segwit_encode("bc", 0, b"\\x00"*20)',
    'ngu.codecs.segwit_encode("bc", 1, b"\\x01"*32)',
    # real BIP-173 vectors -- the previous one here was a bogus address that
    # errored on BOTH backends, so segwit_decode was never value-compared.
    'repr(ngu.codecs.segwit_decode("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"))',
    'repr(ngu.codecs.segwit_decode("tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7"))',
    'repr(ngu.codecs.segwit_decode("BC1SW50QGDZ25J"))',
    'repr(ngu.codecs.segwit_decode("bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0"))',
    # --- hdnode ---
    'H(ngu.hdnode.HDNode().from_master(b"\\x00"*32).privkey())',
    'H(ngu.hdnode.HDNode().from_master(b"\\x00"*32).pubkey())',
    'H(ngu.hdnode.HDNode().from_master(b"seed"*8).chain_code())',
    'str(ngu.hdnode.HDNode().from_master(b"\\x00"*32).my_fp())',
    'ngu.hdnode.HDNode().from_master(b"\\x00"*32).serialize(0x0488ade4, True)',
    'ngu.hdnode.HDNode().from_master(b"\\x00"*32).serialize(0x0488b21e, False)',
    'H(ngu.hdnode.HDNode().from_master(b"\\x00"*32).derive(0, False).privkey())',
    'H(ngu.hdnode.HDNode().from_master(b"\\x00"*32).derive(44, True).privkey())',
    'str(ngu.hdnode.HDNode().from_master(b"\\x00"*32).derive(5, True).child_number())',
    'str(ngu.hdnode.HDNode().from_master(b"\\x00"*32).derive(5, True).depth())',
    'str(ngu.hdnode.HDNode().from_master(b"\\x00"*32).derive(5, True).parent_fp())',
    'H(ngu.hdnode.HDNode().from_master(b"\\x00"*32).addr_help())',
    'ngu.hdnode.HDNode().from_master(b"\\x00"*32).addr_help(0)',
    # round-trip via serialize/deserialize
    '(lambda n, m: (str(m.deserialize(n.serialize(0x0488ade4, True))), H(m.privkey()))[-1])'
    '(ngu.hdnode.HDNode().from_master(b"\\x00"*32), ngu.hdnode.HDNode())',
    # --- secp256k1 ---
    'H(ngu.secp256k1.keypair(b"\\x01"*32).privkey())',
    'H(ngu.secp256k1.keypair(b"\\x01"*32).pubkey().to_bytes())',
    'H(ngu.secp256k1.keypair(b"\\x01"*32).pubkey().to_bytes(True))',
    'str(len(ngu.secp256k1.keypair(b"\\x01"*32).pubkey().to_bytes(False)))',
    'H(ngu.secp256k1.pubkey(ngu.secp256k1.keypair(b"\\x02"*32).pubkey().to_bytes()).to_bytes())',
    # ecdh must be the hashed variant, not a raw point
    'H(ngu.secp256k1.keypair(b"\\x01"*32).ecdh_multiply('
    'ngu.secp256k1.keypair(b"\\x02"*32).pubkey().to_bytes()))',
    # ECDH must be symmetric
    '"SAME" if ngu.secp256k1.keypair(b"\\x01"*32).ecdh_multiply('
    'ngu.secp256k1.keypair(b"\\x02"*32).pubkey().to_bytes()) == '
    'ngu.secp256k1.keypair(b"\\x02"*32).ecdh_multiply('
    'ngu.secp256k1.keypair(b"\\x01"*32).pubkey().to_bytes()) else "DIFFER"',
    # sign/recover round-trip: signatures may differ, recovered pubkey must not
    '(lambda k, d: H(ngu.secp256k1.sign(k, d, 0).verify_recover(d).to_bytes()))'
    '(ngu.secp256k1.keypair(b"\\x03"*32), ngu.hash.sha256s(b"message"))',
    '(lambda k, d: "OK" if ngu.secp256k1.sign(k, d, 0).verify_recover(d).to_bytes() '
    '== k.pubkey().to_bytes() else "MISMATCH")'
    '(ngu.secp256k1.keypair(b"\\x03"*32), ngu.hash.sha256s(b"message"))',
    'str(len(ngu.secp256k1.sign(ngu.secp256k1.keypair(b"\\x03"*32), '
    'ngu.hash.sha256s(b"m"), 0).to_bytes()))',
    # THE signature comparison. Everything above only checked that a signature
    # recovers to the right pubkey and is 65 bytes long -- which any correct
    # ECDSA implementation satisfies with a completely different nonce. The
    # fork's actual claim is that RFC6979 + the counter-as-extra-entropy hook
    # reproduce libngu's bytes EXACTLY, and until now no committed harness
    # compared a single signature byte. psbt.py's ecdsa_grind_sign walks
    # counter=0,1,2,... for a low-R signature, so cover that range.
    'H(ngu.secp256k1.sign(ngu.secp256k1.keypair(b"\\x03"*32), '
    'ngu.hash.sha256s(b"message"), 0).to_bytes())',
    'H(ngu.secp256k1.sign(ngu.secp256k1.keypair(b"\\x03"*32), '
    'ngu.hash.sha256s(b"message"), 1).to_bytes())',
    'H(ngu.secp256k1.sign(ngu.secp256k1.keypair(b"\\x03"*32), '
    'ngu.hash.sha256s(b"message"), 2).to_bytes())',
    'H(ngu.secp256k1.sign(ngu.secp256k1.keypair(b"\\x03"*32), '
    'ngu.hash.sha256s(b"message"), 3).to_bytes())',
    # a second key/digest, so the match is not a property of one vector
    'H(ngu.secp256k1.sign(b"\\x11"*32, ngu.hash.sha256s(b"tx"), 1).to_bytes())',
    # raw-privkey and keypair forms must sign identically
    '"SAME" if ngu.secp256k1.sign(b"\\x03"*32, ngu.hash.sha256s(b"m"), 2).to_bytes() '
    '== ngu.secp256k1.sign(ngu.secp256k1.keypair(b"\\x03"*32), '
    'ngu.hash.sha256s(b"m"), 2).to_bytes() else "DIFFER"',
    # the counter must actually reach the nonce: different counter, different sig
    '"DISTINCT" if len({ngu.secp256k1.sign(b"\\x03"*32, '
    'ngu.hash.sha256s(b"m"), c).to_bytes() for c in range(4)}) == 4 else "COLLIDED"',
    # counters whose truncated 32-bit value has bit 31 set. Both backends take
    # the raw word as RFC6979 extra entropy, so these must be byte-identical to
    # each other and distinct from the counter-0 signature. The shim used to
    # clamp a negative counter to 0, which collapsed all three onto counter 0.
    'H(ngu.secp256k1.sign(b"\\x03"*32, ngu.hash.sha256s(b"m"), -1).to_bytes())',
    'H(ngu.secp256k1.sign(b"\\x03"*32, ngu.hash.sha256s(b"m"), 2**31).to_bytes())',
    'H(ngu.secp256k1.sign(b"\\x03"*32, ngu.hash.sha256s(b"m"), 2**32-1).to_bytes())',
    '"COLLAPSED" if ngu.secp256k1.sign(b"\\x03"*32, ngu.hash.sha256s(b"m"), -1)'
    '.to_bytes() == ngu.secp256k1.sign(b"\\x03"*32, ngu.hash.sha256s(b"m"), 0)'
    '.to_bytes() else "DISTINCT"',
    # --- aes ---
    'H(ngu.aes.CTR(b"\\x00"*32).cipher(b"hello world"))',
    'H(ngu.aes.CTR(b"\\x00"*32, b"\\x01"*16).cipher(b"hello world"))',
    # CTR statefulness: split calls must equal one call
    '"SAME" if (lambda a, b: a.cipher(b"abc") + a.cipher(b"def") == b.cipher(b"abcdef"))'
    '(ngu.aes.CTR(b"\\x07"*32), ngu.aes.CTR(b"\\x07"*32)) else "DIFFER"',
    # CTR across a block boundary
    '"SAME" if (lambda a, b: a.cipher(b"x"*10) + a.cipher(b"y"*20) == '
    'b.cipher(b"x"*10 + b"y"*20))'
    '(ngu.aes.CTR(b"\\x08"*32), ngu.aes.CTR(b"\\x08"*32)) else "DIFFER"',
    # copy() must branch the keystream without disturbing the original
    '"SAME" if (lambda a: (a.copy().cipher(b"1234") == a.copy().cipher(b"1234")))'
    '(ngu.aes.CTR(b"\\x09"*32)) else "DIFFER"',
    'H(ngu.aes.CBC(True, b"\\x00"*32, b"\\x00"*16).cipher(b"\\x11"*32))',
    # CBC decrypt must invert encrypt
    '"SAME" if ngu.aes.CBC(False, b"\\x00"*32, b"\\x00"*16).cipher('
    'ngu.aes.CBC(True, b"\\x00"*32, b"\\x00"*16).cipher(b"\\x11"*32)) == b"\\x11"*32 '
    'else "DIFFER"',
    # ngu.random.uniform() is only deterministic at the bounds libngu treats as
    # <= 1 -- but there it must be exactly 0, and the shim used to sample all of
    # [0,2**32) instead. Four draws: a false "True" needs 2**-128, not 2**-32.
    'str(all(ngu.random.uniform(-1) == 0 for _ in range(4)))',
    'str(all(ngu.random.uniform(2**31) == 0 for _ in range(4)))',
    'str(all(ngu.random.uniform(2**32-1) == 0 for _ in range(4)))',
    'str(all(ngu.random.uniform(2**32) == 0 for _ in range(4)))',
]



# ---------------------------------------------------------------------------
# Cases that DO differ today, recorded with the exact outcome expected from
# each backend. These are open findings, not decisions -- the point is that
# they cannot change silently, in either direction.
# ---------------------------------------------------------------------------
#
# Currently EMPTY: every value this harness compares is byte-identical. The
# machinery stays because an empty allowlist is a claim, and it should have to
# be edited -- visibly, in a diff -- for that claim to stop being true.
# ---------------------------------------------------------------------------
KNOWN_DIFFS = {
}
CASES = CASES + sorted(KNOWN_DIFFS)


# ---------------------------------------------------------------------------
# Backend identity probe.
#
# Without this, pointing both paths at the SAME binary produces a green
# "64 identical, 0 differ" report -- the harness cannot tell it is comparing a
# build to itself, which makes every result below meaningless. Verified: copying
# coldcard-mpy over coldcard-mpy-tz used to pass with exit 0.
#
# So positively identify each backend first, using a KNOWN intentional
# divergence: ngu.random.bytes(-1) hard-crashes libngu (SIGBUS, no exception)
# and raises ValueError on the trezor backend.
# ---------------------------------------------------------------------------
PROBE = ("import ngu\n"
         "try:\n"
         "    ngu.random.bytes(-1)\n"
         "    print('no-raise')\n"
         "except Exception as e:\n"
         "    print(type(e).__name__)\n")


def identify(binary):
    r = subprocess.run([str(binary), "-c", PROBE], capture_output=True, text=True,
                       timeout=60)
    out = r.stdout.strip()
    if not out and r.returncode != 0:
        return "libngu"          # crashed without raising
    if out == "ValueError":
        return "trezor"
    return "unknown(%s rc=%d)" % (out, r.returncode)


def check_backends():
    a, b = identify(LIBNGU), identify(TREZOR)
    print("backend probe: %s -> %s   |   %s -> %s"
          % (LIBNGU.name, a, TREZOR.name, b))
    if a == b:
        print("\nFATAL: both binaries behave identically on the probe, so they are\n"
              "almost certainly the same build. Every comparison below would be\n"
              "vacuously 'identical'. Rebuild both backends and re-run.")
        return False
    if a != "libngu" or b != "trezor":
        print("\nFATAL: could not positively identify both backends "
              "(expected libngu / trezor).")
        return False
    return True


PREAMBLE = "import ngu\nfrom ubinascii import hexlify as H\n"


def run(binary, expr):
    prog = PREAMBLE + "print(%s)\n" % expr
    try:
        r = subprocess.run([str(binary), "-c", prog], capture_output=True,
                           timeout=60, text=True)
    except subprocess.TimeoutExpired:
        return "TIMEOUT"
    if r.returncode != 0:
        last = [x for x in r.stderr.strip().splitlines() if x.strip()]
        return "ERROR: " + (last[-1] if last else "rc=%d" % r.returncode)
    return r.stdout.strip()


def main():
    for b in (LIBNGU, TREZOR):
        if not b.exists():
            print("missing binary: %s" % b)
            return 2

    if not check_backends():
        return 2

    same = differ = both_err = known = 0
    problems = []
    fired = set()

    for expr in CASES:
        a = run(LIBNGU, expr)
        b = run(TREZOR, expr)
        short = expr if len(expr) < 62 else expr[:59] + "..."
        if a == b:
            if a.startswith("ERROR") or a == "TIMEOUT":
                both_err += 1
                print("  both-err  %-62s %s" % (short, a[:40]))
            elif expr in KNOWN_DIFFS:
                # A recorded divergence that stopped diverging is a change in
                # behaviour too -- most likely someone fixed it. Say so loudly
                # rather than passing, so the entry gets deleted with the fix.
                differ += 1
                problems.append((expr, a, b))
                print("  FIXED?    %-62s" % short)
                print("      both now: %s -- delete this KNOWN_DIFFS entry" % a[:80])
            else:
                same += 1
                print("  ok        %-62s" % short)
        elif expr in KNOWN_DIFFS:
            want_a, want_b, why = KNOWN_DIFFS[expr]
            if a == want_a and b == want_b:
                known += 1
                fired.add(expr)
                print("  known     %-62s libngu=%s trezor=%s" % (short, a, b))
                print("      ^ open finding: %s" % why)
            else:
                differ += 1
                problems.append((expr, a, b))
                print("  DIFFER    %-62s" % short)
                print("      expected libngu=%s trezor=%s" % (want_a, want_b))
                print("      got      libngu=%s trezor=%s" % (a[:60], b[:60]))
        else:
            differ += 1
            problems.append((expr, a, b))
            print("  DIFFER    %-62s" % short)
            print("      libngu: %s" % a[:110])
            print("      trezor: %s" % b[:110])

    total = same + differ + both_err + known
    print("\n%d identical, %d known-differ, %d differ, %d error on both"
          % (same, known, differ, both_err))

    # Comparison floor: a harness that silently compares nothing must not pass.
    if total != len(CASES):
        print("FATAL: only %d of %d cases produced a comparison" % (total, len(CASES)))
        return 2
    if both_err:
        print("FATAL: %d case(s) errored on BOTH backends -- a case that fails "
              "everywhere proves nothing and is probably a broken vector." % both_err)
        return 2
    stale = sorted(set(KNOWN_DIFFS) - fired)
    if stale:
        print("FATAL: %d recorded divergence(s) did not occur as recorded:"
              % len(stale))
        for k in stale:
            print("  %s" % k)
        return 2
    if problems:
        print("\nDiffering cases need review: a divergence may be intended "
              "(nonce derivation) or a bug.")
    return 1 if differ else 0


if __name__ == "__main__":
    sys.exit(main())
