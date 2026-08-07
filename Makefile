# Task runner for this fork. Not part of upstream Coldcard/firmware.
#
# Wraps the working build + test invocations, including the environment
# workarounds documented in TESTING.md.
#
# BACKEND selects which crypto backend the simulator runs, because there are two
# interpreters and testing the wrong one silently proves nothing:
#   BACKEND=tz      (default)  trezor-crypto  -> coldcard-mpy-tz
#   BACKEND=libngu             libngu         -> coldcard-mpy
# Both run from unix/; simulator.py picks the interpreter from $COLDCARD_MPY and
# prints which one it resolved. There used to be a hand-made, gitignored unix-tz/
# for this, which meant the guard against running the wrong backend was a
# directory nothing in the repo creates.
BACKEND ?= tz

PY       := $(CURDIR)/ENV/bin/python
SIM_SOCK := /tmp/ckcc-simulator.sock
SIM_LOG  := $(CURDIR)/.local/sim.log

SIM_DIR  := $(CURDIR)/unix
ifeq ($(BACKEND),tz)
SIM_MPY  := coldcard-mpy-tz
else ifeq ($(BACKEND),libngu)
SIM_MPY  := coldcard-mpy
else
$(error BACKEND must be "tz" or "libngu", got "$(BACKEND)")
endif
SIM_BIN  := $(CURDIR)/external/micropython/ports/unix/$(SIM_MPY)

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

# BACKEND-aware build. This used to be `cd unix && make all` for both backends,
# which builds VARIANT=coldcard-mpy (libngu) -- so `make build BACKEND=tz` produced
# the wrong binary and `make ci BACKEND=tz` silently tested a STALE coldcard-mpy-tz.
MPY_UNIX  := $(CURDIR)/external/micropython/ports/unix
VARIANT_TZ := $(CURDIR)/unix/variant-trezor

.PHONY: build
ifeq ($(BACKEND),tz)
build:
	cd $(MPY_UNIX) && $(MAKE) -j4 VARIANT=coldcard-mpy-tz \
		VARIANT_DIR=$(VARIANT_TZ) CC_TOP=$(CURDIR) DEBUG=1
else
build:
	cd unix && $(MAKE) all
endif

$(SIM_BIN): build

sim-start: $(SIM_BIN)
	@mkdir -p $(dir $(SIM_LOG))
	@ln -sf $(SIM_BIN) $(SIM_DIR)/$(SIM_MPY)
	@if [ ! -S $(SIM_SOCK) ]; then \
		cd $(SIM_DIR) && COLDCARD_MPY=$(SIM_MPY) nohup $(PY) simulator.py --headless > $(SIM_LOG) 2>&1 < /dev/null & \
		for i in $$(seq 1 40); do \
			[ -S $(SIM_SOCK) ] && break; sleep 0.5; \
		done; \
	fi; \
	if [ ! -S $(SIM_SOCK) ]; then \
		echo "ERROR: simulator did not come up; see $(SIM_LOG)"; \
		tail -20 $(SIM_LOG); exit 1; \
	fi; \
	if ! grep -q '^interpreter: .*/$(SIM_MPY) ' $(SIM_LOG); then \
		echo "ERROR: something holds $(SIM_SOCK), but it is not $(SIM_MPY)."; \
		grep '^interpreter:' $(SIM_LOG) || echo "  (no interpreter line in $(SIM_LOG))"; \
		echo "  'make sim-stop' first -- testing the wrong backend proves nothing."; \
		exit 1; \
	fi; \
	echo "simulator up on $(SIM_SOCK)  [BACKEND=$(BACKEND) $(SIM_MPY)]"

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
