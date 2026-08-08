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
make diff                                       # builds BOTH, then runs all three
python3 external/c-modules-trezor/difftest.py   # 80 deterministic cases
python3 external/c-modules-trezor/errtest.py    # 58 bad-input cases, with an
                                                #   allowlist of intended diffs
python3 external/c-modules-trezor/fuzz_codecs.py  # 474 fuzzed base32 inputs
```

`make diff` builds both interpreters first. It used to run the harnesses against
whatever binaries were already on disk, which meant the gate could certify a
stale build against an equally stale reference and report green.

| Check | Result |
|---|---|
| Deterministic crypto, 80 cases | **75 identical, 5 known-differ** |
| ECDSA signatures, grind counters 0–3 | **byte-identical** (serialized bytes compared, two key/digest pairs) |
| ECDSA signatures, counters with bit 31 set | **differ** — see "Known gaps" |
| BIP-39 canonical vector (`abandon…about`) | exact |
| `ecdh_multiply` (hashed, not raw ECDH) | byte-exact |
| BIP32 derive / serialize / fingerprints | identical |
| AES-CTR partial-block state + `copy()` | identical |
| Exception classes, 58 bad inputs | **48 identical, 10 intended** |
| Fuzzed base32, 474 inputs | **0 unexpected differences** (47 of them NUL-bearing) |
| `test_wif.py`, `test_addr.py`, `test_msg.py` | identical pass/fail sets |
| MK4 / Q firmware | build, `rng-code-check` passes |
| Flash | **~39 KB smaller** than libngu |

`external/libngu` is deliberately kept in the tree — it is the reference the
differential tests compare against, and it is what makes the byte-identical
claim checkable rather than asserted.

### Four intentional differences

Found by differential testing and review:

1. **`ngu.random.bytes(-1)` hard-crashes libngu** (SIGBUS, exit 138) with no
   exception. Here it raises `ValueError`. This is a live bug in shipping
   firmware.
2. **`b32_decode` rejects an embedded NUL** where libngu silently truncates.
   libngu's loop is `while (... && *ptr)`, so `"MZXW\x006YTBOI"` decodes to
   `b'fo'` there instead of the full six bytes. That path handles TOTP secrets
   (`users.py`, reachable over USB) and QR payloads (`bbqr.py`), where silently
   shortening secret material is worse than refusing it. Found by
   `fuzz_codecs.py`, not by hand-picked vectors.
3. **`HDNode.derive(idx, False)` refuses an index that already carries bit 31.**
   The two libraries resolve that contradiction *differently* and produce
   **different private keys** for the same call: trezor decides hardened-ness
   from the index bit, libngu obeys its own flag. Rather than silently pick an
   interpretation, this backend rejects it. No firmware caller passes such an
   index, so nothing real is refused. This is the only case found where the two
   backends disagreed on key material.
4. **`ngu.random.reseed()` is a no-op.** In libngu it *replaced* the PRNG state.
   With a kernel CSPRNG / hardware TRNG there is no state a 32-bit value can
   improve, so it does nothing. `shared/mk4.py` still calls it.

Everything else that differed was treated as a bug in this fork and fixed —
including base32's leniency, which turned out to be load-bearing: `teleport.py`
decodes hand-typed passwords and relies on `0→O`, `1→L`, `8→B` remapping.

## The EC math is ~12x slower, and that is fine

trezor-crypto uses its own portable `bignum.c` where libngu used libsecp256k1
with precomputed ecmult tables. Measured on the desktop simulator, both
interpreters built `-Os`:

| | libngu | trezor-crypto |
|---|---|---|
| `secp256k1.sign` x200 | 33 ms | 401 ms |
| `HDNode.derive` x200 | 31 ms | 388 ms |

Not a build artifact: SHA-256 is 24 ms vs 20 ms (trezor *faster*) and a pure
Python loop is 8 ms vs 9 ms. It is specifically the field arithmetic.

This is recorded so nobody re-derives it and panics. It does not matter:

- Coldcard shipped trezor-crypto's EC math until v4.0.0, on hardware no faster
  than an **80 MHz** Cortex-M4 (Mk3). Mk4/Mk5/Q are the same core at 120 MHz.
  Not the same vendored commit as this one, but the same `bignum.c` approach.
- The workload did not grow to compensate. `ownership.py` caps at 764 addresses
  (`MAX_ADDRS_STORED`), builds once, caches to a file and already draws a
  progress bar. Address Explorer renders 10 at a time.

**Not measured on real hardware** — like everything else here.

### Why not keep libsecp256k1 for the EC math?

It is a fair question: libsecp256k1 is the most reviewed EC implementation in
Bitcoin, and the vendored tree already carries the switch. `ecdsa.c` compiles
every entry point as a dispatcher behind `USE_SECP256K1_ZKP_ECDSA`, which is
trezor's own production configuration. Four of the five call sites in the shim
would flip for free; signing would not, because it calls
`tc_ecdsa_sign_digest_ex()` directly for the extra-nonce hook.

Decided against, on these grounds:

- **It would make `make diff` partly tautological.** Two independent
  implementations agreeing byte-for-byte is the entire evidentiary basis of this
  fork. Point both at libsecp256k1 and the ECDSA half compares a library to
  itself.
- It gives back the ~39 KB and reintroduces autotools plus the ecmult
  precompute step into the ARM builds — the dependency whose removal is why the
  change to COLDCARD's own sources is only 9 files.
- The side-channel argument runs the *other* way. See the `ctx_rnd()` note in
  `mod_secp256k1_tz.c`: libsecp256k1 blinds once per signing session,
  `tc_ecdsa_sign_digest_ex()` blinds every signature.

The one real argument for switching is that libsecp256k1 takes `ndata`
natively, so `coldcard-changes.patch` could be deleted and the vendored copy
would be byte-identical to upstream. Worth revisiting only if that patch ever
becomes a problem on a vendor bump. It is additive and reversible; it will not
soon.

## Layout

| Path | What |
|---|---|
| `external/trezor-crypto/` | vendored `crypto/` — see [VENDOR.md](external/trezor-crypto/VENDOR.md) |
| `external/trezor-crypto/coldcard-changes.patch` | the entire fork of trezor's code: 4 files, +55/−11, additive |
| `external/c-modules-trezor/ngutz/` | the `ngu` shim (~1,890 lines of new C) |
| `external/c-modules-trezor/{difftest,errtest,fuzz_codecs}.py` | the differential harnesses |
| `unix/variant-trezor/` | simulator build variant → `coldcard-mpy-tz` |
| `stm32/*/c-modules-trezor/` | per-board module dirs for the ARM builds |

Total change to COLDCARD's own firmware sources: **6 files** — three
`USER_C_MODULES` lines (the swap) and three `MICROPY_PY_URANDOM` lines
(hardening).

This project added its own TRNG seed/clock-error check to `rng.c` in `8c8d3ba6`;
upstream arrived at the same fix independently and better in `82ced47a`, so all
three `rng.c` files were reset to upstream's version and are no longer a
divergence. `COLDCARD_Q1/rng.c` is a symlink to the Mk4 file, so Q follows it;
`stm32/COLDCARD/rng.c` (Mk3, which nothing on `master` builds) went back to
upstream's pre-`82ced47a` state rather than keep an unbuilt, unverified variant
of the check.

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

- **A TRNG fault during signing leaks key material onto the stack.** On STM32,
  `random_buffer()` raises `OSError` when the hardware RNG faults. That is a
  MicroPython NLR longjmp, so it unwinds straight out of
  `tc_ecdsa_sign_digest_ex()` and skips the `memzero()` of `k`, `randk` and the
  other scalars at the end of that function. Not fixed, because fixing it
  properly means restructuring trezor's signing routine (an `nlr_push` or a
  pre-fetched entropy pool), which conflicts with keeping the fork minimal.
  Upstream's `82ced47a` added a fault raise to `rng_get_or_fault()` on the same
  path, so this is no longer specific to the fork — but it only raises after
  three failed attempts, so the window is narrower than a bare check would be.
- **Signature counters with bit 31 set do not match libngu.**
  `mod_secp256k1_tz.c` clamps a negative counter to 0; libngu's `k1.c` has no
  clamp and passes the raw truncated word to RFC6979 as extra nonce entropy. So
  `sign(k, d, -1)`, `sign(k, d, 2**31)` and `sign(k, d, 2**32-1)` all return the
  **counter-0 signature** here, and three distinct signatures there. Not
  reachable: `psbt.py`'s `ecdsa_grind_sign` only counts up from 0. Recorded in
  `difftest.py`'s `KNOWN_DIFFS`; deleting the clamp restores exact parity.
- **`ngu.random.uniform()` differs on negative and bit-31 bounds.** It casts to
  `uint32_t` before the `mx <= 1` test, so `uniform(-1)` samples `[0, 2**32)`
  where libngu returns 0. Callers pass 5, 1000, 2048 and `1<<28`. Separately,
  libngu asserts `bit_length(mx) < 31`, so it raises `AssertionError` at bounds
  ≥ `2**30` where this backend returns a value.
- **`ngu.random.reseed()` accepts any object.** The no-op is deliberate (see
  above), but it also dropped libngu's argument type check, so `reseed(None)`
  raises `TypeError` there and silently succeeds here.
- **Never run on real hardware.**
- The `keypair` and `ngu.hash.sha512` objects have no finaliser, so key material
  is not wiped on GC. This **matches libngu**, so it was left alone rather than
  silently diverging — but it is a weakness in both.
- `ngu.ec`, `ngu.cert`, `nip19_*`, Schnorr/`xonly_pubkey`, and `HDNode.censor()`
  are not implemented. Nothing outside libngu's own test suite uses them.
