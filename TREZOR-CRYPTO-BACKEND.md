# FRANKENCARD — the trezor-crypto backend

> Read [DISCLAIMER.md](DISCLAIMER.md) first. This is a hobby project that can
> brick devices and lose funds.

## Why "Frankencard"

Because that is what it is: the crypto organ of one hardware wallet transplanted
into another, stitched up and jolted alive. Naming it anything more respectable
would imply a level of assurance this does not have.

The joke is load-bearing. If a name like "Coldvault" made you feel safe flashing
it, the name would be lying. This one tells you what you are dealing with.

## What this is

COLDCARD's crypto has come from **libngu** (Coinkite's own library: cifra for
hashes and AES, libsecp256k1 for EC) since v4.0.0. Before that it used
**trezor-crypto**.

This fork puts trezor-crypto back, as a drop-in replacement: the MicroPython
module is still called `ngu`, exposes the same names with the same signatures
and the same semantics, and **nothing in `shared/` was changed**. It uses
trezor-crypto's own pure-C ECDSA (`ecdsa.c` + `bignum.c` + `curves.c`), so no
libsecp256k1 is involved at all.

## Why

A low-entropy defect existed in COLDCARD v4.0.0–6.5.1. `ngu.random` produced
every byte as `CHIP_TRNG_32() ^ yasmarang()`, where `CHIP_TRNG_32()` was
`rng_get()`. With `MICROPY_HW_ENABLE_RNG (0)`, that symbol resolved to
MicroPython's *own* yasmarang PRNG, because the board's `rng.c` exported
`random_buffer()` — trezor-crypto's hook shape — and never exported `rng_get`.
Result: two chained PRNGs, no hardware entropy, ~40 bits on Mk3 and ~72 on
Mk4/Q.

Coinkite fixed it and added an `arm-none-eabi-nm` build assertion. Per their
Security Advisory, seeds are trustworthy from 5.6.0 (Mk4/Mk5), 1.5.0Q (Q1),
4.2.0 (Mk3) and 6.6.0 (Edge) onward. **Current official firmware is fine** —
anyone with a seed generated between 2021 and July 2026 should follow
[their advisory](https://blog.coinkite.com/coldcard-mk3-seed-generation-warning/),
not this repo.

The interesting part is *why the guard rails all failed*:

- libngu's own `#ifndef MICROPY_HW_ENABLE_RNG → #error "get a HW TRNG plz"`
  never fired, because `#ifndef` passes when a macro is **defined as 0**. That
  bug is still present upstream in libngu today.
- The TRNG liveness check (`if(chip == last) fail`) can't detect a PRNG, which
  never repeats consecutive outputs.
- `testing/test_rng.py` ran **dieharder** and passed for five years. Statistical
  tests measure *distribution*, not entropy — a PRNG seeded with 40 bits passes
  every one of them. Worse, that test defaults to the simulator, where libngu
  uses `arc4random()`; it never exercised the device path at all.

So the goal here is structural: make the entropy path incapable of that failure
rather than merely fixed.

## The entropy path now

On hardware, this shim deliberately does **not** define `random_buffer()` —
each board's `stm32/COLDCARD*/rng.c` already provides it (its header still reads
*"compat/replacement for trezor-crypto/rand.[ch]"*; it was shaped for this hook
all along). So the chain is:

```
trezor-crypto  ->  random_buffer()  ->  rng_get_or_fault()  ->  STM32 TRNG
```

**No PRNG anywhere in it.** On the desktop simulator, `random_buffer()` goes
straight to `arc4random_buf()` — the kernel CSPRNG, with no whitening layer.

Additionally, `MICROPY_PY_URANDOM (0)` is now set on all three boards, which
removes MicroPython's `extmod/modurandom.c` — and its yasmarang PRNG — from the
firmware binary entirely (verified: 0 matching symbols). Nothing imported it,
but it was one `import urandom` away from being reachable. Coinkite had already
set this on the *simulator* (`unix/variant/mpconfigvariant.h`, "PDG: not
wanted") where it does not actually take effect; the boards never had it.

## Evidence

Three harnesses run the same expression against both the libngu-backed and
trezor-backed interpreters and require identical output:

```bash
make diff                                       # runs all three
python3 external/c-modules-trezor/difftest.py   # 64 deterministic cases
python3 external/c-modules-trezor/errtest.py    # 51 bad-input cases, with an
                                                #   allowlist of intended diffs
python3 external/c-modules-trezor/fuzz_codecs.py  # 427 fuzzed base32 inputs
```

| Check | Result |
|---|---|
| Deterministic crypto, 64 cases | **64 identical** |
| ECDSA signatures, grind counters 0–3 | **byte-identical** |
| BIP-39 canonical vector (`abandon…about`) | exact |
| `ecdh_multiply` (hashed, not raw ECDH) | byte-exact |
| BIP32 derive / serialize / fingerprints | identical |
| AES-CTR partial-block state + `copy()` | identical |
| Exception classes, 51 bad inputs | **47 identical, 3 intended** |
| Fuzzed base32, 427 inputs | **0 unexpected differences** |
| `test_wif.py`, `test_addr.py`, `test_msg.py` | identical pass/fail sets |
| MK4 / Q firmware | build, `rng-code-check` passes |
| Flash | **~39 KB smaller** than libngu |

`external/libngu` is deliberately kept in the tree — it is the reference the
differential tests compare against, and it is what makes the byte-identical
claim checkable rather than asserted.

### Three intentional differences

All are cases where libngu is worse, found by differential testing:

1. **`ngu.random.bytes(-1)` hard-crashes libngu** (SIGBUS, exit 138) with no
   exception. Here it raises `ValueError`. This is a live bug in shipping
   firmware.
2. **`b32_decode` rejects an embedded NUL** where libngu silently truncates.
   libngu's loop is `while (... && *ptr)`, so `"MZXW\x006YTBOI"` decodes to
   `b'fo'` there instead of the full six bytes. That path handles TOTP secrets
   (`users.py`, reachable over USB) and QR payloads (`bbqr.py`), where silently
   shortening secret material is worse than refusing it. Found by
   `fuzz_codecs.py`, not by hand-picked vectors.
3. **`ngu.random.reseed()` is a no-op.** In libngu it *replaced* the PRNG state.
   With a kernel CSPRNG / hardware TRNG there is no state a 32-bit value can
   improve, so it does nothing. `shared/mk4.py` still calls it.

Everything else that differed was treated as a bug in this fork and fixed —
including base32's leniency, which turned out to be load-bearing: `teleport.py`
decodes hand-typed passwords and relies on `0→O`, `1→L`, `8→B` remapping.

## Layout

| Path | What |
|---|---|
| `external/trezor-crypto/` | vendored `crypto/` — see [VENDOR.md](external/trezor-crypto/VENDOR.md) |
| `external/trezor-crypto/coldcard-changes.patch` | the entire fork of trezor's code: 4 files, +55/−11, additive |
| `external/c-modules-trezor/ngutz/` | the `ngu` shim (~1,900 lines of new C) |
| `external/c-modules-trezor/{difftest,errtest,fuzz_codecs}.py` | the differential harnesses |
| `unix/variant-trezor/` | simulator build variant → `coldcard-mpy-tz` |
| `stm32/*/c-modules-trezor/` | per-board module dirs for the ARM builds |

Total change to COLDCARD's own tracked files: **6 files** — three
`USER_C_MODULES` lines (the swap) and three `MICROPY_PY_URANDOM` lines (the
hardening).

## Building

See [TESTING.md](TESTING.md) for the full environment, including the macOS
toolchain workarounds.

```bash
# simulator
cd unix && make setup && make ngu-setup && CFLAGS_EXTRA="-Wno-error" make
cd ../external/micropython/ports/unix && \
  CFLAGS_EXTRA="-Wno-error" make VARIANT=coldcard-mpy-tz \
    VARIANT_DIR=$PWD/../../../../unix/variant-trezor CC_TOP=$PWD/../../../..

# firmware (needs arm-none-eabi-gcc)
cd stm32 && make -f MK-Makefile setup && make -f MK-Makefile   # or Q1-Makefile
```

## Hardware coverage

| Target | Build | Status |
|---|---|---|
| **Mk4 / Mk5** | `stm32/MK-Makefile` (`BOARD=COLDCARD_MK4`, `HW_MODEL=mk`) | builds, `rng-code-check` passes, simulator boots as `--mk4` and `--mk5` |
| **Q** | `stm32/Q1-Makefile` | builds, `rng-code-check` passes, simulator boots as `--q1` |
| **Mk3** | *none on `master`* | **untested, unbuilt** |

Mk4 and Mk5 are one firmware image — upstream's README says a build for Mk5
"supports the Mk4 without any functional differences" — so they are covered by
the same verification, and `--mk5` is the simulator's default.

**Mk3 is not covered.** `stm32/COLDCARD/` (the Mk3 board) had its
`USER_C_MODULES` and `MICROPY_PY_URANDOM` lines changed alongside the others for
consistency, but **no makefile on `master` builds `BOARD=COLDCARD`** — Mk3
firmware lives on the `v4-legacy` branch, which is where its RNG fix and the
4.2.0 release in Coinkite's advisory come from. Those two edits are therefore
inert here and have never been compiled. Anyone reviving Mk3 or cherry-picking to
`v4-legacy` must build and re-verify it from scratch.

(Commit `31026cc3`'s message claims Mk3 is covered. It is wrong; this table is
correct.)

## Known gaps

- **Never run on real hardware.**
- The `keypair` and `ngu.hash.sha512` objects have no finaliser, so key material
  is not wiped on GC. This **matches libngu**, so it was left alone rather than
  silently diverging — but it is a weakness in both.
- `ngu.ec`, `ngu.cert`, `nip19_*`, Schnorr/`xonly_pubkey`, and `HDNode.censor()`
  are not implemented. Nothing outside libngu's own test suite uses them.
