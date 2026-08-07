# 🧟 FRANKENCARD

### *Two wallets. One of them didn't consent.*

[![frankencard](https://github.com/tobomobo/frankencard/actions/workflows/trezor-backend.yml/badge.svg)](https://github.com/tobomobo/frankencard/actions/workflows/trezor-backend.yml)

COLDCARD firmware with its crypto library **`libngu` cut out and
[trezor-crypto](https://github.com/trezor/trezor-firmware/tree/master/crypto)
stitched in**. An organ transplant between two hardware wallets, sewn up and
jolted alive.

> ## ⚠️ DO NOT USE WITH REAL FUNDS
>
> Unaudited hobby project. **It can permanently brick your COLDCARD and it can
> lose your bitcoin.** Firmware that crashes before login is unrecoverable; a
> flaw in key generation is invisible until the money is gone. **Never run on
> physical hardware** — only the desktop simulator. Not affiliated with Coinkite
> or SatoshiLabs. → **[DISCLAIMER.md](DISCLAIMER.md)**
>
> Own a COLDCARD? The [Security Advisory](#security-advisory) below is Coinkite's
> and it is the urgent one. This repo is not.

## What it is

A **drop-in backend swap**. The MicroPython module is still called `ngu`, exposes
the same names with the same signatures and semantics, and **nothing in
`shared/` changed** — the firmware doesn't know it happened.

- Uses trezor-crypto's own **pure-C ECDSA** (`ecdsa.c`/`bignum.c`/`curves.c`),
  the arrangement COLDCARD used before v4.0.0. **No libsecp256k1** at all.
- On hardware the entropy path is `trezor-crypto → random_buffer() → STM32 TRNG`
  — **no PRNG anywhere in it**. MicroPython's `urandom` PRNG is no longer
  compiled in either: 0 yasmarang symbols in the binary, down from 6.
- Builds the simulator **and** real MK4/Mk5 + Q firmware. Flash is **~39 KB
  smaller** than libngu.

| Where the code lives | |
|---|---|
| `external/c-modules-trezor/ngutz/` | the `ngu` shim — ~1,875 lines of new C |
| `external/trezor-crypto/` | vendored upstream `crypto/`, MIT |
| [`coldcard-changes.patch`](external/trezor-crypto/coldcard-changes.patch) | **the whole fork of trezor's code: 4 files, +55/−11, additive** |
| `external/libngu/` | kept on purpose — the reference the tests diff against |

Changed in COLDCARD's own tree: **6 files** — three `USER_C_MODULES` lines and
three `MICROPY_PY_URANDOM` lines.

## Is it equivalent? (tested, not asserted)

```bash
make diff      # runs the same expression on both backends, demands equality
```

| | |
|---|---|
| Deterministic crypto, 68 cases | **68 identical** |
| ECDSA signatures, incl. low-R grind | **byte-identical** |
| BIP-39 vector, `ecdh_multiply`, BIP32 derive/serialize | byte-exact |
| Exception classes, 51 bad inputs | 47 identical, 3 intended |
| Fuzzed base32, 427 inputs | 0 unexpected differences |
| `test_wif` / `test_addr` / `test_msg` | identical pass/fail sets |
| MK4 + Q firmware | build, `rng-code-check` passes |

Four differences are intentional: `bytes(-1)`
SIGBUSes there and raises `ValueError` here; `b32_decode` silently **truncates**
at an embedded NUL there and is rejected here (it decodes TOTP secrets, so
shortening one quietly is worse than refusing it); and `reseed()` is a no-op
because there's no PRNG state left to reseed.

## Run it

```bash
cd unix && make setup && make ngu-setup && CFLAGS_EXTRA="-Wno-error" make
make diff                       # prove the backends agree
make ci                         # boot the simulator + smoke test
make ci BACKEND=libngu          # ...and the same against the original
```

## Docs

[DISCLAIMER.md](DISCLAIMER.md) · [TREZOR-CRYPTO-BACKEND.md](TREZOR-CRYPTO-BACKEND.md)
(what changed and why) · [TESTING.md](TESTING.md) (setup, sharp edges) ·
[VENDOR.md](external/trezor-crypto/VENDOR.md) (provenance)

COLDCARD firmware is MIT **+ Commons Clause** ([COPYING-CC](COPYING-CC)) — modify
and publish yes, **sell no**. trezor-crypto is MIT.

---

*Below: Coinkite's original README, verbatim. Note reproducible builds from this
tree will **not** match their official binaries.*

# Security Advisory

- Versions from 2021 to July 2026 had a bug which produced poor entropy.
- Any secrets generated on a COLDCARD in that period should be regenerated and 
  funds moved on chain **immediately**.
- Master seeds can only be trusted from releases after these levels:
    - 5.6.0 (Mk4, MK5) 
    - 1.5.0Q (Q1) 
    - 4.2.0 (Mk3)
    - 6.6.0 (Edge Mk/Q)
- Using a BIP-39 passphrase mitigates some of the risk, although it relies
  on the entropy your passphrase adds. Dice rolls introduced into the secret
  provide 2.5 bits of entropy per roll.
- [Blog post and updates](https://blog.coinkite.com/coldcard-mk3-seed-generation-warning/)
- [Technical background on the bug](https://blog.coinkite.com/entropy-technical-backgrounder/)
---

## Upstream

Coinkite's original README is archived verbatim at
**[UPSTREAM-README.md](UPSTREAM-README.md)** — it documents upstream COLDCARD, not
this fork. For building *this*, see [TESTING.md](TESTING.md).
