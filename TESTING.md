# Testing and local environment

Verified working 2026-08-05 on macOS 27 (arm64), Apple clang, Python 3.14.

## The real gate: differential tests

```bash
python3 external/c-modules-trezor/difftest.py   # 64 cases; must report "0 differ"
python3 external/c-modules-trezor/errtest.py    # 48 cases; 1 known divergence
```

These need **both** interpreters built (`unix/coldcard-mpy` and
`coldcard-mpy-tz`) and no simulator running. They are what proves this backend
is a faithful replacement; `.github/workflows/trezor-backend.yml` runs them on
every push, along with both ARM firmware builds and a check that no yasmarang
symbol is linked in.

The one accepted divergence is `ngu.random.bytes(-1)`: libngu SIGBUSes, this
backend raises `ValueError`. Anything else differing is a bug.

## Smoke test

```bash
make ci
```

From the repo root, ~11s. Builds the simulator if needed, starts it headless,
runs a libngu self-check plus a two-test pytest smoke gate, stops the simulator.
`make help` lists the other targets.

## What `make ci` does not cover

It is a **smoke gate, not a test run.** Be honest about this when reporting
results — passing it means the toolchain works, not that a change is correct.

- It runs **2 of ~2000 tests**. The suite is 66 files and drives a simulated
  device over a socket with keypresses, so whole files take minutes:
  `test_seed_xor.py` was only 45% done after 4 minutes. It passes, it is just
  slow. For a real run, name the file and wait:
  `make test PYTEST_ARGS="test_seed_xor.py -q"`.
- Parts of the suite need real hardware or a card reader.
- It runs against the **simulator**, which uses different crypto primitives than
  the device (see the simulator/device warning in [AGENTS.md](AGENTS.md)).
- `testing/test_rng.py` is excluded — it needs `dieharder`
  (`brew install dieharder`) and, more importantly, it only tests distribution,
  which proves nothing about entropy. Run it with `--dev` against real hardware
  or not at all.
- No reproducible-build check. That needs Docker and `docs/notes-on-repro.md`.

## Environment quirks this works around

These are all local-environment problems, not repo bugs, except where noted.

**Homebrew is unavailable in this account** (no sudo). System packages have to be
installed from another session. Currently satisfied: `automake autoconf libtool
protobuf xterm sdl3 sdl3_image`, plus `sdl2`/`SDL2_image`.

**`macos-mpy.patch` is stale.** It suppresses `unused-but-set-variable`,
`array-bounds` and `unknown-warning-option`, but current Apple clang also errors
on `-Wgnu-folding-constant` (`py/emitnative.c`) and
`-Wunterminated-string-initialization` (`py/emitinlinethumb.c`,
`extmod/moductypes.c`). Do **not** edit the patch — a submodule re-checkout
discards it. Override from outside instead:

```bash
make -C external/micropython/mpy-cross CFLAGS_EXTRA="-Wno-error"
cd unix && CFLAGS_EXTRA="-Wno-error" make    # must be an env var, not a make arg,
                                            # so it reaches the sub-make
```

**`pyscard` will not build** (needs macOS PCSC headers). It is annotated
optional in `testing/requirements.txt` — desktop NFC-V reader only. Filter that
line out; everything else installs.

**Pinned `pytest==6.2.5` cannot run on Python 3.14** — it uses `ast.Str`, removed
in 3.12. `pip install -U pytest` (9.x) works and the tests still pass.

**`pysecp256k1` needs a shared libsecp256k1** that is not installed. One is built
and checked in at `.local/lib/libsecp256k1.dylib` (gitignored). To rebuild it,
copy `external/libngu/libs/secp256k1` elsewhere first — the in-tree copy is
already configured by `make ngu-setup` and refuses to configure twice:

```bash
cp -R external/libngu/libs/secp256k1 /tmp/k1src && cd /tmp/k1src
make distclean
./configure --enable-module-recovery --enable-module-ecdh \
            --enable-module-extrakeys --enable-module-schnorrsig \
            --disable-benchmark --disable-tests --disable-exhaustive-tests
make -j4 && cp .libs/libsecp256k1*.dylib <repo>/.local/lib/
```

## From-scratch setup

```bash
git submodule update --init external/libngu external/micropython \
                            external/ckcc-protocol external/mpy-qr
cd external/libngu && git submodule update --init libs/cifra libs/secp256k1 && cd -
cd external/micropython && git apply ../../macos-mpy.patch && cd -
make -C external/micropython/mpy-cross CFLAGS_EXTRA="-Wno-error"
python3 -m venv ENV && ./ENV/bin/pip install -U pip pytest
grep -v '^pyscard' testing/requirements.txt > /tmp/t.txt
./ENV/bin/pip install -r /tmp/t.txt -r cli/requirements.txt -r unix/requirements.txt \
                      -r external/ckcc-protocol/requirements.txt \
                      namedlist pyusb "ckcc-protocol[cli]"
cd unix && make setup && make ngu-setup && CFLAGS_EXTRA="-Wno-error" make
```

`unix/make setup` also builds a vanilla micropython for comparison; it is slow
and not required for the simulator itself.

## Running things by hand

Simulator, headless (no XQuartz needed — `simulator.py:788`):

```bash
cd unix && ../ENV/bin/python simulator.py --headless
```

Booted successfully when it prints `Start: mainline`; it listens on
`/tmp/ckcc-simulator.sock`. Add `brew install xterm && brew install --cask
xquartz` for the graphical window.

Poke libngu with no simulator at all — useful for crypto questions:

```bash
cd unix && ./coldcard-mpy -c \
  "import ngu; from ubinascii import hexlify as H; print(H(ngu.random.bytes(32)))"
```

Note `ngu.bip39` does not exist as a C module; the BIP-39 wordlist is Python
(`external/libngu/ngu/bip39.py`), frozen separately.

## Building for real hardware

Needs the ARM toolchain, not yet installed:

```bash
brew install --cask gcc-arm-embedded
```

Then `cd stm32 && make -f MK-Makefile` (Mk4/Mk5) or `-f Q1-Makefile` (Q). Read
the bricking warning in [AGENTS.md](AGENTS.md) before flashing anything.

The ARM build is also the only place `rng-code-check` (`stm32/shared.mk`) runs —
it uses `arm-none-eabi-nm` and cannot run against the simulator.

## Trezor comparison environment

A Trezor emulator was built for design comparison. It needs, beyond the packages
above: rust `nightly-2026-03-16` (pinned in their `shell.nix`), `uv sync`, and
three workarounds — put the nightly toolchain on `PATH` directly (brew's
standalone `rust` shadows rustup and ignores `rustup override`), relax `-Werror`
in `core/embed/models/build.rs`, and set `AR=llvm-ar` because their
`make_static_library` runs `ar rcs` with zero objects, which GNU ar accepts and
BSD/Apple ar rejects. Build with
`xtask build firmware --emulator -m t3t1 --pyopt=false` — omitting `--pyopt=false`
produces a binary whose C module and Python source disagree about `__debug__`.
