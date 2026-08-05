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
    'repr(ngu.codecs.segwit_decode("bc1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqk9"))',
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
]

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

    same = differ = both_err = 0
    problems = []

    for expr in CASES:
        a = run(LIBNGU, expr)
        b = run(TREZOR, expr)
        short = expr if len(expr) < 62 else expr[:59] + "..."
        if a == b:
            if a.startswith("ERROR") or a == "TIMEOUT":
                both_err += 1
                print("  both-err  %-62s %s" % (short, a[:40]))
            else:
                same += 1
                print("  ok        %-62s" % short)
        else:
            differ += 1
            problems.append((expr, a, b))
            print("  DIFFER    %-62s" % short)
            print("      libngu: %s" % a[:110])
            print("      trezor: %s" % b[:110])

    print("\n%d identical, %d differ, %d error on both" % (same, differ, both_err))
    if problems:
        print("\nDiffering cases need review: a divergence may be intended "
              "(nonce derivation) or a bug.")
    return 1 if differ else 0


if __name__ == "__main__":
    sys.exit(main())
