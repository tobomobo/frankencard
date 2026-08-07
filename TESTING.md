# Testing and local environment

Verified working 2026-08-05 on macOS 27 (arm64), Apple clang, Python 3.14.

## The real gate: differential tests

```bash
make diff        # runs all three harnesses
# difftest.py    68 cases; must report "0 differ" and "0 error on both"
# errtest.py     51 cases; 4 intended divergences, 0 unexpected
# fuzz_codecs.py 427 fuzzed base32 inputs
```

These need **both** interpreters built (`unix/coldcard-mpy` and
`coldcard-mpy-tz`) and no simulator running. They are what proves this backend
is a faithful replacement; `.github/workflows/trezor-backend.yml` runs them on
every push, along with both ARM firmware builds and a check that no yasmarang
symbol is linked in.

There are **four** accepted divergences, all listed in errtest.py's
`EXPECTED_DIVERGENCES` (negative byte count, embedded NUL in base32, an
ambiguous hardened bit in `derive()`, and `reseed()` being a no-op). The harness fails on any *other* difference, and
refuses to run at all if the two binaries fail a backend-identity probe.

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

- It runs **2 of ~250 collected tests**. The suite is 66 files and drives a simulated
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
cd unix && COLDCARD_MPY=coldcard-mpy-tz ../ENV/bin/python simulator.py --headless
```

`COLDCARD_MPY` names the interpreter to run, relative to `unix/`; it defaults to
`coldcard-mpy`, the libngu one. Whichever you pick, the first line of output is
`interpreter: ... -> ...` with the resolved path — read it, because the two
binaries are indistinguishable once they are talking on the socket.

Booted successfully when it prints `Start: mainline`; it listens on
`/tmp/ckcc-simulator.sock`.

### Memory pressure: `COLDCARD_HEAP`

The simulator runs with a 9 MB MicroPython heap. `unix/variant/sim_psram.py`
fakes the Mk4's PSRAM as a 4 MB `bytearray` **on that heap**, leaving ~5 MB
free. A Mk4 has 632 KB of SRAM in total (`stm32/COLDCARD_MK4/layout.ld:21`) and
its PSRAM is a separate external chip that never touches the heap.

So the simulator has order-of-magnitude more room than the product, and code
that would exhaust a real device — the reason `shared/psbt.py` streams instead
of buffering — cannot fail here. `COLDCARD_HEAP` sets the heap so you can test
under something closer to device pressure:

```bash
cd unix && COLDCARD_HEAP=5m COLDCARD_MPY=coldcard-mpy-tz ../ENV/bin/python simulator.py --headless
```

Measured free heap after the PSRAM allocation:

| `COLDCARD_HEAP` | free      | note |
| --------------- | --------- | ---- |
| `9m` (default)  | 5012 KB   | ~8x the device's entire SRAM |
| `5m`            | 964 KB    | roughly device-like, given 64-bit objects are wider than ARM ones |
| 4.6m – 4.9m     | —         | **does not boot**; avoid |
| `4300k`         | boots     | below the failure band |

This is a calibration dial, not equivalence. Two caveats before you trust a
result from it:

- The failure band around 4.6–4.9 MB is not monotonic and is a host GC artifact
  of allocating 4 MB contiguously out of a barely-larger heap. It says nothing
  about the device. Do not tune into it.
- You cannot reach device parity by lowering this number, because the 4 MB
  PSRAM mock sits on the heap and sets a hard ~4 MB floor. Getting closer means
  moving the PSRAM mock off the MicroPython heap (`mmap`), which nobody has
  done.

A test that passes at `9m` and fails at `5m` is worth reading; it is the only
memory signal this simulator can give you.

For the graphical screen on macOS use `--no-xterm` instead of `--headless`:

```bash
cd unix && COLDCARD_MPY=coldcard-mpy-tz ../ENV/bin/python simulator.py --q1 --no-xterm
```

The simulated screen is SDL2, which is native Cocoa on macOS. Only upstream's
REPL console is an xterm, i.e. an X11 app — so without `--no-xterm` you must
install and run XQuartz purely to host a terminal, for a window macOS draws by
itself. `--no-xterm` sends the firmware's output to your terminal instead.
Upstream's XQuartz route still works if you prefer a separate REPL window.

Poke libngu with no simulator at all — useful for crypto questions:

```bash
cd unix && ./coldcard-mpy -c \
  "import ngu; from ubinascii import hexlify as H; print(H(ngu.random.bytes(32)))"
```

Note `ngu.bip39` does not exist as a C module; the BIP-39 wordlist is Python
(`external/libngu/ngu/bip39.py`), frozen separately.

## Building for real hardware

Needs the ARM toolchain (`brew install --cask gcc-arm-embedded`); it is
installed here and both firmware images have been built with it.

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
