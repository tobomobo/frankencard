# Task runner for this fork. Not part of upstream Coldcard/firmware.
#
# Wraps the working build + test invocations, including the environment
# workarounds documented in TESTING.md.
#
# BACKEND selects which crypto backend the simulator runs, because there are two
# interpreters and testing the wrong one silently proves nothing:
#   BACKEND=tz      (default)  trezor-crypto  -> coldcard-mpy-tz, run from unix-tz/
#   BACKEND=libngu             libngu         -> coldcard-mpy,    run from unix/
BACKEND ?= tz

PY       := $(CURDIR)/ENV/bin/python
SIM_SOCK := /tmp/ckcc-simulator.sock
SIM_LOG  := $(CURDIR)/.local/sim.log

ifeq ($(BACKEND),tz)
SIM_BIN  := $(CURDIR)/external/micropython/ports/unix/coldcard-mpy-tz
SIM_DIR  := $(CURDIR)/unix-tz
else ifeq ($(BACKEND),libngu)
SIM_BIN  := $(CURDIR)/external/micropython/ports/unix/coldcard-mpy
SIM_DIR  := $(CURDIR)/unix
else
$(error BACKEND must be "tz" or "libngu", got "$(BACKEND)")
endif

# pysecp256k1 needs an explicit path to a shared libsecp256k1; see TESTING.md.
export PYSECP_SO := $(CURDIR)/.local/lib/libsecp256k1.dylib

# Current Apple clang errors on warnings macos-mpy.patch does not cover.
export CFLAGS_EXTRA := -Wno-error

# Smoke gate. This suite drives a simulated device over a socket with
# keypresses, so whole files take minutes (test_seed_xor.py was only 45% done at
# 4min; it passes, it is just slow). These node IDs are verified to run in <10s.
# For a real run, name files yourself and expect to wait:
#   make test PYTEST_ARGS="test_seed_xor.py -q"
PYTEST_ARGS ?= test_bip39pw.py -k test_tmp_on_xprv_master -q

.PHONY: help ci build test sim-start sim-stop clean-local

help:
	@echo "make diff        - differential tests: both backends must agree  <- REAL gate"
	@echo "make build       - build the unix simulator for BACKEND"
	@echo "make sim-start   - start the simulator headless, wait for socket"
	@echo "make sim-stop    - stop it"
	@echo "make test        - run the smoke pytest subset (simulator must be up)"
	@echo "make ci          - diff + build + start + test + stop"
	@echo ""
	@echo "BACKEND=tz|libngu         which crypto backend (default: tz)"
	@echo "PYTEST_ARGS=\"file.py -q\"  run more than the smoke gate (slow)"
	@echo "See TESTING.md for what this covers and what it does not."

# The differential harnesses need both interpreters and no simulator running.
.PHONY: diff
diff:
	python3 external/c-modules-trezor/difftest.py
	python3 external/c-modules-trezor/errtest.py
	python3 external/c-modules-trezor/fuzz_codecs.py

$(SIM_BIN) build:
	cd unix && $(MAKE) all

sim-start: $(SIM_BIN)
	@mkdir -p $(dir $(SIM_LOG))
	@if [ -S $(SIM_SOCK) ]; then echo "simulator already running"; exit 0; fi; \
	cd $(SIM_DIR) && nohup $(PY) simulator.py --headless > $(SIM_LOG) 2>&1 < /dev/null & \
	for i in $$(seq 1 40); do \
		[ -S $(SIM_SOCK) ] && break; sleep 0.5; \
	done; \
	if [ ! -S $(SIM_SOCK) ]; then \
		echo "ERROR: simulator did not come up; see $(SIM_LOG)"; \
		tail -20 $(SIM_LOG); exit 1; \
	fi; \
	echo "simulator up on $(SIM_SOCK)  [BACKEND=$(BACKEND)]"

sim-stop:
	@pkill -f "simulator.py --headless" 2>/dev/null && echo "simulator stopped" || echo "not running"
	@rm -f $(SIM_SOCK)

test:
	@if [ ! -S $(SIM_SOCK) ]; then echo "ERROR: simulator not running; use 'make sim-start'"; exit 1; fi
	@echo "--- ngu smoke check via $(notdir $(SIM_BIN)) (no simulator needed) ---"
	@$(SIM_BIN) -c "import ngu; b=ngu.random.bytes(32); \
assert len(b)==32 and len(set(b))>16; assert len(ngu.hash.sha256d(b))==32; \
assert len(ngu.secp256k1.keypair().pubkey().to_bytes())==33; print('ngu ok')"
	cd testing && $(PY) -m pytest $(PYTEST_ARGS)

ci:
	@$(MAKE) sim-start
	@$(MAKE) test; rv=$$?; $(MAKE) sim-stop; exit $$rv

clean-local:
	rm -f $(SIM_LOG)
