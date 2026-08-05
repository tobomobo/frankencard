# Vendored trezor-crypto

This is the `crypto/` subdirectory of [trezor/trezor-firmware][tf], vendored
rather than added as a submodule: the upstream repo is very large and only this
one subdirectory is needed.

[tf]: https://github.com/trezor/trezor-firmware

## Provenance

| | |
|---|---|
| Source | `https://github.com/trezor/trezor-firmware` |
| Path | `crypto/` |
| Commit | `ab95f08f33ff52f93f7697be603dc1ce3c02fa46` |
| Commit date | 2026-08-04 |
| Retrieved | 2026-08-05 |

## License

`crypto/LICENSE` is **MIT** (Copyright 2013 Tomas Dzetkulic, Pavol Rusnak).
All original copyright headers are preserved.

Note that trezor-firmware's `core/` tree is **GPL-3.0** — none of it is used
here. Only `crypto/` is vendored, and every file compiled into this firmware
was checked to carry no GPL header. See the file list in
`../c-modules-trezor/ngutz/micropython.mk` (`TZ_FILES`).

## What was removed

- `crypto/tests/` (~107 MB of test vectors)
- `crypto/fuzzer/`

Nothing else was deleted. If you want to re-verify this vendored copy against
upstream, clone that commit and diff `crypto/` against this directory; the only
differences should be the two deletions above plus the patch below.

## Local modifications

**Four files, +55/−11 lines, purely additive.** Every hunk is tagged
`COLDCARD-ADDED`, and no existing function signature or behaviour changed —
`init_rfc6979()` and `tc_ecdsa_sign_digest()` keep their exact prototypes and
now delegate to the new variants with `NULL`.

The complete delta is committed as **`coldcard-changes.patch`** so it can be
reviewed on its own. It reverses cleanly against this tree:

```bash
cd external/trezor-crypto && patch -p1 --dry-run -R < coldcard-changes.patch
```

### Why the change was needed

`shared/psbt.py`'s `ecdsa_grind_sign()` searches for low-R signatures by
re-signing with an incrementing counter. libngu passed that counter to
libsecp256k1's RFC6979 as *extra nonce data* (`data32`). trezor-crypto's
`ecdsa_sign_digest()` has no equivalent hook — only an `is_canonical` callback.

Rather than change how signing works, `init_rfc6979_ex()` threads 32 bytes of
extra entropy into the HMAC-DRBG seed as `priv || hash || extra`, which is the
same layout libsecp256k1 uses for `key32 || msg32 || data32`.

The payoff: signatures are **byte-identical to the libngu build for every
counter value**, verified by `../c-modules-trezor/difftest.py`. Without this,
signatures would still be valid but different bytes.

## Upgrading

1. Clone the new upstream commit, copy `crypto/` over this directory.
2. Delete `tests/` and `fuzzer/`.
3. `patch -p1 < coldcard-changes.patch`
4. Re-run `difftest.py` and `errtest.py` — both must stay green.
5. Update the commit hash in the table above.
