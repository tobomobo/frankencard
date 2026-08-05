# 🧟 FRANKENCARD

### *Two wallets. One of them didn't consent.*

[![frankencard](https://github.com/tobomobo/frankencard/actions/workflows/trezor-backend.yml/badge.svg)](https://github.com/tobomobo/frankencard/actions/workflows/trezor-backend.yml)

COLDCARD firmware with its crypto library (`libngu`) cut out and
[trezor-crypto](https://github.com/trezor/trezor-firmware/tree/master/crypto)
stitched in its place. An organ transplant between two hardware wallets, sewn up
and jolted alive.

> ## ⚠️ DO NOT USE WITH REAL FUNDS
>
> **This is an unaudited hobby project. It can permanently brick your COLDCARD
> and it can lose your bitcoin.** Custom firmware that crashes before the login
> sequence completes is unrecoverable, and a subtle flaw in key generation or
> signing is invisible until the money is already gone.
>
> **It has never run on physical hardware.** Everything verified so far was
> verified in the desktop simulator.
>
> **Not affiliated with, endorsed by, or reviewed by Coinkite Inc. or
> SatoshiLabs.** Do not report issues with this fork to either company.
>
> Read **[DISCLAIMER.md](DISCLAIMER.md)** before going any further.

## Why

COLDCARD v4.0.0–6.5.1 had a low-entropy defect: `ngu.random` produced every byte
as `CHIP_TRNG_32() ^ yasmarang()`, and `CHIP_TRNG_32()` resolved to *another*
software PRNG because the board file exported `random_buffer()` — trezor-crypto's
hook shape — but never exported the `rng_get` symbol libngu expected. Two chained
PRNGs, no hardware entropy, ~40 bits of seed on Mk3.

**Coinkite fixed it** (`ca724637`, 2026-07-31) and shipped a build-time assertion
with it. Current official firmware is not affected. This is an architecture
experiment, not a warning about their product.

What is interesting is *why every guard rail failed*: libngu's own
`#ifndef MICROPY_HW_ENABLE_RNG` guard never fired, because `#ifndef` passes when
a macro is **defined as 0**. The TRNG liveness check can't detect a PRNG. And
`testing/test_rng.py` ran **dieharder** and passed for five years — statistical
tests measure *distribution*, not entropy, and that test defaulted to the
simulator anyway, where it was really testing `arc4random`.

So the goal here is structural rather than corrective. On hardware the entropy
path is now:

```
trezor-crypto  ->  random_buffer()  ->  rng_get_or_fault()  ->  STM32 TRNG
```

No PRNG anywhere in it. MicroPython's `urandom` PRNG is no longer compiled in
either — 0 yasmarang symbols remain in the firmware binary, where there were 6.

## Is it actually equivalent?

That's the whole claim, so it's tested rather than asserted. Two harnesses run
the same expression against **both** interpreters and require identical output:

```bash
make diff        # difftest.py: 64 cases  +  errtest.py: 48 cases
```

| Check | Result |
|---|---|
| Deterministic crypto, 64 cases | **64 identical** |
| ECDSA signatures, incl. low-R grind counters | **byte-identical** |
| BIP-39 canonical vector (`abandon…about`) | exact |
| `ecdh_multiply`, BIP32 derive / serialize / fingerprints | byte-exact |
| AES-CTR partial-block state + `copy()` | identical |
| Exception classes, 48 bad inputs | **47 identical** |
| `test_wif.py`, `test_addr.py`, `test_msg.py` | identical pass/fail sets |
| MK4 + Q firmware | build, `rng-code-check` passes |
| Flash | **~39 KB smaller** than libngu |

`external/libngu` is kept in the tree on purpose: it's the reference those tests
compare against, which is what makes "byte-identical" checkable.

Two differences are intentional, both where libngu is worse: `ngu.random.bytes(-1)`
hard-crashes libngu (SIGBUS) where this raises `ValueError`, and
`ngu.random.reseed()` is now a no-op because there's no PRNG state left to reseed.

## Try it

```bash
cd unix && make setup && make ngu-setup && CFLAGS_EXTRA="-Wno-error" make
make diff                        # prove the two backends agree
make ci                          # build + boot the simulator + smoke test
make ci BACKEND=libngu           # ...and the same against the original
```

The graphical simulator, seeded with a throwaway test seed:

```bash
cd unix-tz && DISPLAY=:0 ../ENV/bin/python simulator.py --q1   --seed "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
```

## Docs

| | |
|---|---|
| [DISCLAIMER.md](DISCLAIMER.md) | the risks, in full — read this one |
| [TREZOR-CRYPTO-BACKEND.md](TREZOR-CRYPTO-BACKEND.md) | what changed, why, and the layout |
| [TESTING.md](TESTING.md) | environment setup and its many sharp edges |
| [VENDOR.md](external/trezor-crypto/VENDOR.md) | provenance of the vendored library |
| [coldcard-changes.patch](external/trezor-crypto/coldcard-changes.patch) | **the entire fork of trezor's code**: 4 files, +55/−11 |

## License

COLDCARD firmware is MIT **plus the Commons Clause** ([COPYING-CC](COPYING-CC)) —
you may modify and publish it, you may **not sell** it. trezor-crypto is MIT.
Both apply here; see [DISCLAIMER.md](DISCLAIMER.md#licensing).

---

## ─── Upstream COLDCARD README below, preserved verbatim ───

Everything from here down is Coinkite's original README, kept for its build and
code-organization docs. Note two things it says that are **not true of this
fork**: reproducible builds will not match Coinkite's official binaries, and its
`make -f MK4-Makefile repro` command references a file that no longer exists
(it is `stm32/MK-Makefile`).

# COLDCARD Hardware Wallet

Coldcard is an Affordable, Ultra-secure & Verifiable Hardware Wallet for Bitcoin.
Get yours at [Coldcard.com](http://coldcard.com)

[Follow @COLDCARDwallet on Twitter](https://twitter.com/coldcardwallet) to keep up
with the latest updates and security alerts.

![coldcard logo](https://coldcard.com/static/images/coldcard-logo-nav.png)

![Mk5 coldcard picture front](https://coldcard.com/static/images/mk5-front.png)

## Quick Links

- [Latest firmware changes and updates](releases/ChangeLog.md)
- [PGP signature file](releases/signatures.txt)
- [Firmware binaries](https://coldcard.com/downloads)

## Reproducible Builds

To have confidence this source code tree is the same as the binary on your device,
you can rebuild it from source and get **exactly the same bytes**. This process
has been automated using Docker. Steps are as follows:

1. Install [Docker](https://www.docker.com) and start it.
2. Install [make (GNUMake)](https://www.gnu.org/software/make/) if you don't already have it.
3. Checkout a specific version of the code, and start the process.

    ```shell
    git clone https://github.com/Coldcard/firmware.git
    cd firmware
    # DOWNLOAD https://coldcard.com/downloads
    # get a copy of binary into ./releases/2026-03-05T2052-v5.5.0-mk-coldcard.dfu
    git checkout 2026-03-05T2052-v5.5.0
    cd stm32
    make -f MK4-Makefile repro
    ```

4. At the end of the process a clear confirmation message is shown, or the differences.
5. Build products can be found `firmware/stm32/built`.
6. If you do not trust the results of `make repro` refer to `docs/notes-on-repro.md`
   which breaks down the process.
7. Process for Q firmware is the same, but change `MK4-Makefile` in last step to `Q1-Makefile`

## Long-Lived Branches

We are now maintaining two branches: `master` and `edge`.

"Edge" will contain features that may not be ready for prime time,
such as Taproot or Miniscript. Our standards for releasing new Edge
versions are lower, so we can iterate faster and get these advancements
out to other developers.

Q and Mk series share the same code base. Individual files that are added,
or removed, can be see in differences between `shared/manifest_mk4.py`
and `shared/manifest_q1.py`. Common files are in `shared/manifest.py`.
Firmware built for Mk5, supports the Mk4 without any functional differences.


## Check-out and Setup

**NOTE** This is the `master` branch and covers the latest hardware (Mk and Q).
See branch `v4-legacy` for firmware which supports only Mk3/Mk2 and earlier.

Do a checkout, recursively, to get all the submodules:

```shell
git clone --recursive https://github.com/Coldcard/firmware.git
```

Already checked-out and getting git errors? Do this:

```shell
git fetch
git reset --hard origin/master
```

Alternatively, to get the latest release, you checkout a tagged branch:

```shell
git clone https://github.com/Coldcard/firmware.git
cd firmware
git checkout $(git describe --match "20*" --abbrev=0)
git submodule update --init --recursive
```

Do not use a path with any spaces in it. The Makefiles do not handle
that well and we're not planning to fix it.

Keep in mind that python requirements may change between versions,
so at the top level, do this command:

```shell
pip install -r requirements.txt
```

### macOS

[Python 3.5 or higher](https://www.python.org) and [Homebrew](https://brew.sh) is required.

If working on an ARM-based MacOS system, you may want to create a
new shell with `arch -x86_64 bash` before starting, or continuing
to work on this source tree.

#### Setup and run the desktop simulator

You'll probably need to install at least these packages:

```shell
brew install sdl2 xterm swig
brew install --cask xquartz gcc-arm-embedded
```

Used to be these were needed as well:

```shell
brew tap PX4/px4
brew search px4/px4/gcc-arm-none-eabi
```

Then install the newest version, currently 83:

```shell
brew install px4/px4/gcc-arm-none-eabi-83
```

You may need to `brew upgrade gcc-arm-embedded` because we need 10.2 or higher.

Then:

```shell
brew install automake autogen virtualenv
virtualenv -p python3 ENV
source ENV/bin/activate (or source ENV/bin/activate.csh based on shell preference)
pip install -U pip
pip install -r requirements.txt
# apply micropython patch
pushd external/micropython
git apply ../../macos-mpy.patch
popd
make -C external/micropython/mpy-cross
cd unix; make setup && make ngu-setup && make && ./simulator.py
```

You may need to reboot to avoid a `DISPLAY is not set` error.

The next time you want to run the simulator, you can simply do

```shell
source ENV/bin/activate && cd unix && ./simulator.py
```

#### Building the firmware

- `cd ../cli; pip install --editable .`
- `cd ../stm32; make setup && make; make firmware-signed.dfu`
- The resulting file, `firmware-signed.dfu` can be loaded directly onto a Coldcard, using this
  command (already installed based on above)
- `ckcc upgrade firmware-signed.dfu`

Which looks like this:

```shell
[ENV] [firmware/stm32 42] ckcc upgrade firmware-signed.dfu  
675328 bytes (start @ 293) to send from 'firmware-signed.dfu'
Uploading  [##########--------------------------]   29%  0d 00:01:04
```

#### Big Sur Issues

`defaults write org.python.python ApplePersistenceIgnoreState NO` will suppress a warning about `Python[22580:10101559] ApplePersistenceIgnoreState: Existing state will not be touched. New state will be written to...`

See <https://bugs.python.org/issue32909>

### Linux

All steps you need to install and run the Coldcard simulator on Ubuntu 20.04:


```shell
# Install (system) requirements, tools and libraries
apt install build-essential git python3 python3-pip libudev-dev gcc-arm-none-eabi libffi-dev xterm swig libpcsclite-dev python-is-python3 autoconf libtool python3-venv

# Get sources, this takes a long time (because of external libraries), then open
git clone --recursive https://github.com/Coldcard/firmware.git
cd firmware

# Apply address patch
# if unix/linux_addr.patch exists use below command
# not needed in current revision
# git apply unix/linux_addr.patch

#  * below is needed for ubuntu 24.04
pushd external/micropython
git apply ../../ubuntu24_mpy.patch
popd
#  * 


# Create Python virtual environment and activate it
python3 -m venv ENV  # or virtualenv -p python3 ENV
source ENV/bin/activate

# Install dependencies
pip install -U pip setuptools
pip install -r requirements.txt #general requirements
pip install pysdl2-dll # Ubuntu needs this dependency

# Build the Coldcard simulator
cd unix
pushd ../external/micropython/mpy-cross/
make  # mpy-cross
popd
make setup
make ngu-setup
make

# Run the simulator in the active virtualenv
./simulator.py

# Later, if you want to run it (after a reboot). This assumes you extracted the git repo in ~ (home)
cd ~/firmware
source ENV/bin/activate
cd unix
./simulator.py
```

Also make sure that you have your python3 symlinked to python.

## Code Organization

Top-level dirs:

`shared`

- shared code between desktop test version and real-deal
- expected to be largely in python, and higher-level
- code exclusive to the Mk4 or Mk5 will be listed in `manifest_mk4.py`, and
  to the Q will be listed in `manifest_q1.py`

`unix`

- unix (macOS) version for testing/rapid dev
- this is a simulator for the product

`testing`

- test cases and associated data

`stm32`

- embedded binaries (and building), for actual product hardware
- final target is a binary file for loading onto hardware

`external`

- code from other projects, ie. the dreaded submodules

`graphics`

- images which ship as part of the final product (icons)

`stm32/bootloader`

- 32k of factory-set code that you cannot change (Mk3)
- however, you can inspect what code is on your coldcard and compare to this.

`stm32/mk4-bootloader`
`stm32/q1-bootloader`

- 128k of factory-set code that you cannot change
- however, you can inspect what code is on your coldcard and compare to this.

`hardware`

- schematic and bill of materials for the Coldcard, all versions.

`unix/work/...`

- `/MicroSD/*` files on "simulated" microSD card

- `/VirtDisk/*` simulated emulated virtual Disk files.

- `/settings/*.aes` persistent settings for Simulator

## Support

Found a bug? Email: support@coinkite.com

