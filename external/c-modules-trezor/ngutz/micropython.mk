# Trezor-crypto backed replacement for libngu.
# Autodetected by py/py.mk based on this file's name.
#
# Provides the same `ngu` MicroPython module, implemented on trezor-crypto
# (external/trezor-crypto/crypto) instead of libngu's cifra + libsecp256k1.
#
# Uses trezor-crypto's own pure-C ECDSA (ecdsa.c/bignum.c/curves.c), which is
# the arrangement Coldcard used before v4.0.0 -- no libsecp256k1 involved.

# Self-locating: realpath resolves the symlink the stm32 boards use to reach
# this directory, so the same file works for the unix and ARM builds without
# depending on CC_TOP (which only the unix Makefile defines).
TZ_TOP := $(realpath $(USERMOD_DIR)/../../trezor-crypto/crypto)

TZ_FILES = sha2.c ripemd160.c hasher.c hmac.c pbkdf2.c memzero.c \
           bignum.c ecdsa.c curves.c secp256k1.c nist256p1.c rand.c \
           rfc6979.c hmac_drbg.c consteq.c \
           base58.c base32.c segwit_addr.c bip32.c \
           blake256.c blake2b.c groestl.c sha3.c \
           aes/aescrypt.c aes/aeskey.c aes/aestab.c aes/aes_modes.c

SHIM_FILES = modngu_tz.c mod_hdnode_tz.c mod_secp256k1_tz.c mod_codecs_tz.c mod_aes_tz.c

CFLAGS_USERMOD += -I$(TZ_TOP) -I$(USERMOD_DIR)

# Lean build: no ed25519/SLIP-10 curves (bip32.c references them heavily),
# no BIP32/BIP39 caches (we do not use the cached derivation entry points),
# AES key sizes to match libngu's accepted 16/24/32-byte keys.
CFLAGS_USERMOD += -DUSE_BIP32_25519_CURVES=0 -DUSE_BIP32_CACHE=0 \
                  -DUSE_BIP39_CACHE=0 -DUSE_RFC6979=1 \
                  -DAES_128 -DAES_192 -DAES_VAR

# trezor-crypto is warning-clean against its own pinned compiler, not this one.
CFLAGS_USERMOD += -Wno-unknown-warning-option -Wno-unused-function \
                  -Wno-sign-compare -Wno-unterminated-string-initialization \
                  -Wno-gnu-folding-constant

SRC_USERMOD += $(addprefix $(USERMOD_DIR)/, $(SHIM_FILES))
SRC_USERMOD += $(addprefix $(TZ_TOP)/, $(TZ_FILES))

# EOF

FROZEN_MANIFEST += $(USERMOD_DIR)/manifest.py
