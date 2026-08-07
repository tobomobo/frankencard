# Agent instructions — FRANKENCARD

## What this repo is

**FRANKENCARD**: an **unofficial hobby fork** of Coinkite's `Coldcard/firmware`
that replaces the crypto library `libngu` with **trezor-crypto**. Work happens on `master`
(the fork was merged there); `upstream` is the fetch-only Coinkite remote.

The name is deliberate and the tone is part of the safety story — it signals a
transplant held together with stitches, not a product. Keep that register: do not
smooth the docs into sounding like assured, shippable firmware.

Read [TREZOR-CRYPTO-BACKEND.md](TREZOR-CRYPTO-BACKEND.md) for what changed and
why, and [DISCLAIMER.md](DISCLAIMER.md) for the risk posture. Two things follow
for you:

- **Do not shape work around sending PRs to Coinkite.** This is a fork, not a
  contribution queue. `git remote` may still point at upstream — check before
  suggesting any push.
- **Be accurate and fair about the bug that motivated this.** Coinkite fixed the
  v4.0.0 entropy defect and published a Security Advisory (top of `README.md`,
  from upstream) giving the trustworthy release levels: 5.6.0 Mk4/Mk5, 1.5.0Q Q1,
  4.2.0 Mk3, 6.6.0 Edge. Official firmware is not affected. Never imply
  otherwise in code comments, docs, or commit messages — and prefer citing those
  versions and their blog posts over a commit SHA, since that is what a reader
  with an affected device actually needs.

Upstream's own docs and code are *the subject of review*, not authority. When a
doc and the code disagree, the code wins and the doc is a finding worth
reporting.

## Quality gate

```bash
make diff        # all three differential harnesses -- the REAL gate
make ci          # build + boot the simulator + smoke test
```

**The differential harnesses are the real gate.** They run the same expression
against both interpreters — libngu-backed and trezor-backed — and require
identical output. If a change makes them diverge, that is a finding to explain,
not a diff to accept. `.github/workflows/trezor-backend.yml` enforces this plus
both ARM builds on every push.

`make ci` is only a smoke test (2 of ~250 collected tests). See [TESTING.md](TESTING.md)
for what it does not cover and for the environment quirks it works around.

## Hard invariants

**Keep the fork of trezor-crypto minimal.** `external/trezor-crypto/` is vendored
upstream code. Only four files differ (+55/−11, purely additive, tagged
`COLDCARD-ADDED`). Prefer solving things in the shim
(`external/c-modules-trezor/ngutz/`) over editing trezor's code — that is how
`random_buffer`, `tc_fault_handler` and `explicit_bzero` are handled. If you do
change it, **regenerate `coldcard-changes.patch`** and keep it reversible:

```bash
cd external/trezor-crypto && patch -p1 --dry-run -R < coldcard-changes.patch
```

**Reproducible builds no longer match Coinkite's**, by construction — this fork
changes the binary. Internal determinism still matters, so flag build-config
changes explicitly, but do not claim upstream repro parity. See
`docs/notes-on-repro.md`.

**There are two simulator binaries and it is easy to test the wrong one.**
`unix/coldcard-mpy` is libngu-backed (the reference);
`coldcard-mpy-tz` is trezor-backed. `testing/` connects to whichever simulator
holds `/tmp/ckcc-simulator.sock`, so **always confirm which one is running**
before believing a test result.

**The simulator is not the device, specifically for crypto.** Entropy source
differs per platform: on unix the shim uses `arc4random_buf()`, on STM32 it uses
the board's hardware TRNG. `testing/` defaults to the simulator unless given
`--dev`. A passing test may be exercising the host CSPRNG and telling you nothing
about the firmware — that is how a critical entropy bug survived five years of a
passing `testing/test_rng.py`.

**Statistical tests cannot detect low entropy.** `testing/test_rng.py` runs
dieharder. A PRNG seeded with 40 bits passes every distribution test ever
written. When reasoning about randomness, trace *provenance* — which function
actually produced the bytes — never distribution. The correct pattern is the
`rng-code-check` target in `stm32/shared.mk`, which fails the build via
`arm-none-eabi-nm` if the wrong `rng_get` symbol linked in.

**Flashing can permanently brick a device.** Per `docs/dev-access.md`: the
bootrom cannot be replaced, an unsigned build always shows a warning screen and
forced delay on Mk4+, and a crash before the boot/login sequence completes is
fatal with no recovery path. Never present a flashing step as routine, and never
run one without explicit confirmation.

## Handle with extreme care

Changes to these files can silently destroy user funds. Read the whole file and
every caller before editing; prefer reporting a finding over making the edit.

| Area | Files |
| --- | --- |
| Seed generation & entropy | `shared/seed.py`, `shared/mk4.py` (`rng_seeding`), `stm32/COLDCARD*/rng.c`, `external/c-modules-trezor/ngutz/modngu_tz.c` |
| The crypto shim (all of it) | `external/c-modules-trezor/ngutz/*.c` — ~1,890 lines handling private keys |
| Secret storage | `shared/stash.py`, `shared/nvstore.py`, `shared/pincodes.py` |
| Signing & verification | `shared/psbt.py`, `shared/sigheader.py`, `stm32/*/sigheader.h` |
| Secure elements | `shared/callgate.py`, `docs/secure-elements.md` |

When editing the shim, mark any intentional behaviour difference from libngu with
a `DIVERGENCE:` comment saying what and why. Silent behaviour changes in a wallet
are how people lose money — and one such change (strict base32) was caught only
because `teleport.py` relies on libngu's lenient decoder for hand-typed
passwords.

## Repo map

Only the non-obvious parts:

- `shared/` — the MicroPython firmware source, shared across all hardware. Most
  logic lives here.
- `shared/manifest.py`, `manifest_mk4.py`, `manifest_q1.py` — which files get
  frozen into which hardware build. A new file in `shared/` does nothing until
  it is listed in a manifest.
- `stm32/` — ARM build. `MK-Makefile` (Mk4 **and** Mk5 — one image), `Q1-Makefile`
  (Q). Plain `stm32/Makefile` is a convenience shim; it builds a **debug Mk**
  build (`DEBUG_BUILD=1 -f MK-Makefile`), despite its own header claiming Q1.
  **Nothing on `master` builds Mk3** (`BOARD=COLDCARD`) — that lives on
  `v4-legacy`. The `stm32/COLDCARD/` edits in this fork are inert and unverified;
  do not claim Mk3 support. See the coverage table in
  [TREZOR-CRYPTO-BACKEND.md](TREZOR-CRYPTO-BACKEND.md).
- `unix/` — desktop simulator, builds the same `shared/` code against
  micropython's unix port.
- `external/libngu` — Coinkite's crypto library. **No longer compiled into
  anything.** Kept deliberately: it is the reference the differential tests
  compare against, which is what makes the byte-identical claim checkable rather
  than asserted. Do not delete it. (Its pin is 20 commits behind its upstream,
  and its `#ifndef MICROPY_HW_ENABLE_RNG` guard bug is still unfixed there.)
- `external/trezor-crypto/` — vendored upstream `crypto/`, MIT. See
  [VENDOR.md](external/trezor-crypto/VENDOR.md).
- `external/c-modules-trezor/ngutz/` — the `ngu` shim; this is the new code.
- `unix/variant-trezor/`, `stm32/*/c-modules-trezor/` — build wiring that
  selects the trezor backend without disturbing the libngu build.
- `testing/` — 66 pytest files, driven over a socket against the simulator.
  Note `testing/ckcc_protocol` is a symlink, so `ckcc_protocol` only imports
  when cwd is `testing/`.

## Branches

`master` and `edge` are both maintained; `edge` carries features held to a lower
release bar. Note that **the same fix often lands as different commits on
different branches** — the 2026-07 RNG fix is `ca724637` on `master`,
`b987de50` on `origin/new_edge`, and `45436299` on `origin/v4-legacy`. Always
confirm with `git merge-base --is-ancestor <sha> <branch>` before claiming
something is or is not shipped.

## Known stale docs

Report these rather than trusting them:

- The README's reproducible-build section says `make -f MK4-Makefile repro`. That
  file does not exist; it is `stm32/MK-Makefile`. Neither it nor `Q1-Makefile`
  defines a `repro` target — only `stm32/Makefile` mentions `repro`, and only to
  print a message. (Upstream text, kept below this fork's banner.)
- `stm32/Makefile:4` says it "builds a debug version of Q1 by default". Line 15
  builds `-f MK-Makefile`.
- `macos-mpy.patch` predates current Apple clang and no longer suffices to build.
  See [TESTING.md](TESTING.md).

## Conventions

- Match the surrounding file. This is a 2018-era MicroPython codebase with its
  own idiom; do not modernize style incidentally.
- MicroPython is not CPython: no f-strings in some paths, `bytes` has no
  `.hex()`, use `ubinascii.hexlify`. Check what the target interpreter supports
  before using a stdlib convenience.
- Firmware size matters. `shared/` is frozen into a fixed flash budget.
