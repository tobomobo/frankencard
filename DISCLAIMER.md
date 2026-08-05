# Disclaimer

## FRANKENCARD is a hobby project. It can brick your device and lose your money.

It is called Frankencard because it is a crypto-library transplant between two
hardware wallets. That is a joke about the code, not about the risk — the risk
below is real and none of it is exaggerated for effect.

This is an unofficial, unaudited experiment by a hobbyist. It replaces the
cryptographic library inside COLDCARD firmware. Cryptographic code is exactly
the kind of code where a subtle mistake is invisible until funds are gone.

**Do not put real money anywhere near this.**

### Concretely, what can go wrong

- **Your COLDCARD can be permanently bricked.** Per
  [`docs/dev-access.md`](docs/dev-access.md), custom firmware that crashes before
  the boot and login sequence completes cannot be recovered — there is no way to
  upload a fix afterwards. The device becomes an ornament. This is not a
  theoretical risk; it is the documented behaviour.
- **You can lose bitcoin.** A flaw in key generation, key derivation, or signing
  can produce a wallet that looks perfectly normal and is quietly guessable, or
  signatures that leak your private key. The 2026 entropy incident in COLDCARD's
  own history (see below) is a demonstration that this failure mode is real,
  silent, and can persist for years.
- **Your seed words may not be recoverable elsewhere.** If a derivation path or
  encoding differs from the standard, the words you write down may not restore
  the same wallet in other software.
- **Backups may not be restorable.** Encrypted backup files written by this
  firmware are not guaranteed to be readable by official firmware.

### Status of this code, stated plainly

- **Never run on physical hardware.** The firmware compiles for ARM and the
  build-time assertions pass, but no part of this has executed on a real
  COLDCARD. Everything verified so far was verified in the desktop simulator.
- **Not independently audited.** Roughly 1,900 lines of new C handle private
  keys. It has been differentially tested against the original implementation
  and reviewed, including by automated review passes — but reviewed is not
  audited, and no cryptographer has looked at it.
- **Test coverage is partial.** The differential tests cover the crypto surface
  well. The full COLDCARD test suite does not pass cleanly on unmodified
  upstream either, so "no regressions" here means *identical pass/fail sets
  against the original backend*, not *everything passes*.

### Not affiliated with anyone

Not affiliated with, endorsed by, sponsored by, or reviewed by **Coinkite Inc.**
(COLDCARD) or **SatoshiLabs** (Trezor). Both names appear here only to describe
what this code is derived from. Do not contact either company about this fork.
Bugs here are not their bugs.

### Be fair about the bug that inspired this

This project was motivated by a real low-entropy defect in COLDCARD firmware
v4.0.0–6.5.1, where `ngu.random` drew from two chained software PRNGs instead of
the hardware TRNG because a board file never exported the `rng_get` symbol that
libngu expected.

**Coinkite fixed it**, along with a build-time `arm-none-eabi-nm` assertion that
fails the build if the wrong RNG links in. Per their
[Security Advisory](README.md#security-advisory), master seeds can be trusted
from these releases onward: **5.6.0** (Mk4/Mk5), **1.5.0Q** (Q1), **4.2.0**
(Mk3), **6.6.0** (Edge). See the
[announcement](https://blog.coinkite.com/coldcard-mk3-seed-generation-warning/)
and the [technical backgrounder](https://blog.coinkite.com/entropy-technical-backgrounder/).

**If you generated a seed on a COLDCARD between 2021 and July 2026, act on that
advisory rather than on anything in this repo.** Coinkite's guidance is to
regenerate the secret and move funds on chain immediately. That is real and
urgent; this fork is neither.

This fork is an architectural exercise — "what would it look like to go back to
trezor-crypto, and can the entropy path be made structurally incapable of that
failure?" — **not** a warning about current official firmware, and not a claim
that this code is safer. It has had far less scrutiny than the code it replaces.

### No warranty

Provided as-is, with no warranty of any kind. You accept all risk. If you flash
this and lose a device or lose funds, that outcome is yours alone.

### Licensing

- COLDCARD firmware: MIT **plus the Commons Clause** — see
  [`COPYING-CC`](COPYING-CC). You may use, modify and publish it; you may **not
  sell** it, or sell services whose value derives substantially from it. That
  restriction applies to this fork too.
- trezor-crypto: MIT — see
  [`external/trezor-crypto/crypto/LICENSE`](external/trezor-crypto/crypto/LICENSE)
  and [`external/trezor-crypto/VENDOR.md`](external/trezor-crypto/VENDOR.md).

This summary is not legal advice. Read the licenses.
