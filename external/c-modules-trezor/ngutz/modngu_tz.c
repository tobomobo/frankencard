//
// modngu_tz.c -- the `ngu` MicroPython module, backed by trezor-crypto.
//
// Drop-in replacement for libngu: same module name, same function names, same
// signatures and semantics, so nothing in shared/ needs to change.
//
// Backend differences vs libngu are called out with "DIVERGENCE:" comments.
//
#include "py/obj.h"
#include "py/runtime.h"
#include "py/builtin.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "sha2.h"
#include "ripemd160.h"
#include "hmac.h"
#include "pbkdf2.h"
#include "memzero.h"
#include "rand.h"

#if MICROPY_ENABLE_DYNRUNTIME
#error "Static Only"
#endif

// ---------------------------------------------------------------------------
// Entropy source for trezor-crypto.
//
// crypto/rand.c implements random_uniform()/random_permute() on top of
// random32(), which is an inline calling random_buffer(). The embedder must
// supply random_buffer() -- and NOT defining USE_INSECURE_PRNG is what keeps
// trezor's LCG test PRNG out of the build.
//
// DIVERGENCE (deliberate, and an improvement): libngu computed every byte as
// CHIP_TRNG_32() ^ yasmarang(), where on this platform CHIP_TRNG_32() is
// arc4random(). Here we go straight to the kernel CSPRNG with no PRNG
// whitening layer, so there is no small-state generator that can silently
// become the only entropy source.
// ---------------------------------------------------------------------------
#if defined(MICROPY_PY_STM) && MICROPY_PY_STM
// On real hardware we deliberately do NOT define random_buffer(): the board's
// own stm32/COLDCARD*/rng.c already provides it, reading the STM32 hardware
// TRNG with a DRDY timeout and a hard fault on failure. That file's header
// still says "compat/replacement for trezor-crypto/rand.[ch]" -- it was shaped
// for exactly this hook before v4.0.0, and is correct again now.
//
// The consequence is the point of this whole exercise: on hardware the entropy
// path is trezor-crypto -> random_buffer() -> hardware TRNG, with no PRNG in
// it at all. There is no small-state generator that a missing symbol could
// silently substitute, so the v4.0.0 yasmarang failure cannot recur here.
#else
void random_buffer(uint8_t *buf, size_t len) {
    arc4random_buf(buf, len);
}
#endif

// ---------------------------------------------------------------------------
// Fault handler for trezor-crypto.
//
// Also an embedder hook. crypto/consteq.c calls this when a constant-time
// compare finds its loop did not run to completion -- i.e. suspected fault
// injection. trezor ships fault_handler_noop.c for it, which emits a
// "NOT SUITABLE FOR PRODUCTION USE" #pragma; we supply a real one instead of
// compiling that, so the warning is answered rather than silenced.
// ---------------------------------------------------------------------------
void tc_fault_handler(const char *msg) {
#if defined(MICROPY_PY_STM) && MICROPY_PY_STM
    (void)msg;
    // Bare metal: no stdio, and returning would let the caller proceed as if
    // the compare had succeeded. Halt.
    for(;;) { }
#else
    fprintf(stderr, "\nFATAL: trezor-crypto fault detected: %s\n", msg ? msg : "?");
    abort();
#endif
}

#if defined(MICROPY_PY_STM) && MICROPY_PY_STM
// crypto/memzero.c sees __NEWLIB__ and therefore selects explicit_bzero(), but
// the newlib-nano linked into this firmware does not actually provide it.
// Supplying it here keeps trezor-crypto unmodified. Must stay volatile so the
// optimiser cannot drop the wipe -- that is the entire point of the function.
void explicit_bzero(void *p, size_t n) {
    volatile unsigned char *volatile q = (volatile unsigned char *volatile)p;
    for(size_t i = 0; i < n; i++) {
        q[i] = 0;
    }
}
#endif

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------
STATIC mp_obj_t bytes_from(const uint8_t *p, size_t len) {
    vstr_t v;
    vstr_init_len(&v, len);
    memcpy(v.buf, p, len);
    return mp_obj_new_str_from_vstr(&mp_type_bytes, &v);
}

#define GET_BUF(dst, obj, mode) \
    mp_buffer_info_t dst; mp_get_buffer_raise(obj, &dst, mode)

// ===========================================================================
// ngu.hash
// ===========================================================================

STATIC mp_obj_t tz_sha256s(mp_obj_t arg) {
    GET_BUF(bi, arg, MP_BUFFER_READ);
    uint8_t out[SHA256_DIGEST_LENGTH];
    sha256_Raw(bi.buf, bi.len, out);
    return bytes_from(out, sizeof(out));
}
STATIC MP_DEFINE_CONST_FUN_OBJ_1(tz_sha256s_obj, tz_sha256s);

STATIC mp_obj_t tz_sha256d(mp_obj_t arg) {
    GET_BUF(bi, arg, MP_BUFFER_READ);
    uint8_t out[SHA256_DIGEST_LENGTH];
    sha256_Raw(bi.buf, bi.len, out);
    sha256_Raw(out, sizeof(out), out);
    return bytes_from(out, sizeof(out));
}
STATIC MP_DEFINE_CONST_FUN_OBJ_1(tz_sha256d_obj, tz_sha256d);

// BIP-340 tagged hash: sha256(sha256(tag) || sha256(tag) || msg).
// Third arg true => `tag` is already the 32-byte tag hash.
// (trezor-crypto has no tagged_hash of its own; this is the BIP-340 definition.)
STATIC mp_obj_t tz_sha256t(size_t n_args, const mp_obj_t *args) {
    GET_BUF(tag, args[0], MP_BUFFER_READ);
    GET_BUF(msg, args[1], MP_BUFFER_READ);

    bool pre_hashed = (n_args > 2) && mp_obj_is_true(args[2]);

    uint8_t s0[SHA256_DIGEST_LENGTH];
    if(pre_hashed) {
        if(tag.len != SHA256_DIGEST_LENGTH) {
            mp_raise_ValueError(MP_ERROR_TEXT("tag hash must be 32 bytes"));
        }
        memcpy(s0, tag.buf, sizeof(s0));
    } else {
        sha256_Raw(tag.buf, tag.len, s0);
    }

    SHA256_CTX ctx;
    sha256_Init(&ctx);
    sha256_Update(&ctx, s0, sizeof(s0));
    sha256_Update(&ctx, s0, sizeof(s0));
    sha256_Update(&ctx, msg.buf, msg.len);
    uint8_t out[SHA256_DIGEST_LENGTH];
    sha256_Final(&ctx, out);

    return bytes_from(out, sizeof(out));
}
STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(tz_sha256t_obj, 2, 3, tz_sha256t);

// DIVERGENCE: libngu raises ValueError above 63 bytes (its rmd160.c is a
// single-block implementation). trezor's ripemd160 has no such limit, but the
// cap is kept so behaviour matches -- code that works here works on libngu.
STATIC mp_obj_t tz_ripemd160(mp_obj_t arg) {
    GET_BUF(bi, arg, MP_BUFFER_READ);
    if(bi.len > 63) {
        mp_raise_ValueError(MP_ERROR_TEXT("limited to 63 bytes"));
    }
    uint8_t out[RIPEMD160_DIGEST_LENGTH];
    ripemd160(bi.buf, bi.len, out);
    return bytes_from(out, sizeof(out));
}
STATIC MP_DEFINE_CONST_FUN_OBJ_1(tz_ripemd160_obj, tz_ripemd160);

STATIC mp_obj_t tz_hash160(mp_obj_t arg) {
    GET_BUF(bi, arg, MP_BUFFER_READ);
    uint8_t mid[SHA256_DIGEST_LENGTH];
    uint8_t out[RIPEMD160_DIGEST_LENGTH];
    sha256_Raw(bi.buf, bi.len, mid);
    ripemd160(mid, sizeof(mid), out);
    return bytes_from(out, sizeof(out));
}
STATIC MP_DEFINE_CONST_FUN_OBJ_1(tz_hash160_obj, tz_hash160);

STATIC mp_obj_t tz_pbkdf2_sha512(mp_obj_t pw_in, mp_obj_t salt_in, mp_obj_t rounds_in) {
    GET_BUF(pw, pw_in, MP_BUFFER_READ);
    GET_BUF(salt, salt_in, MP_BUFFER_READ);
    mp_int_t rounds = mp_obj_get_int(rounds_in);

    if(rounds < 1) mp_raise_ValueError(MP_ERROR_TEXT("rounds"));
    if(salt.len == 0) mp_raise_ValueError(MP_ERROR_TEXT("salt"));

    uint8_t out[64];
    pbkdf2_hmac_sha512(pw.buf, pw.len, salt.buf, salt.len, rounds, out, sizeof(out));

    mp_obj_t rv = bytes_from(out, sizeof(out));
    memzero(out, sizeof(out));
    return rv;
}
STATIC MP_DEFINE_CONST_FUN_OBJ_3(tz_pbkdf2_sha512_obj, tz_pbkdf2_sha512);

// --- incremental sha512 object ---

typedef struct _tz_sha512_obj_t {
    mp_obj_base_t base;
    SHA512_CTX ctx;
} tz_sha512_obj_t;

extern const mp_obj_type_t tz_sha512_type;

STATIC mp_obj_t tz_sha512_update(mp_obj_t self_in, mp_obj_t arg) {
    tz_sha512_obj_t *self = MP_OBJ_TO_PTR(self_in);
    GET_BUF(bi, arg, MP_BUFFER_READ);
    sha512_Update(&self->ctx, bi.buf, bi.len);
    return mp_const_none;
}
STATIC MP_DEFINE_CONST_FUN_OBJ_2(tz_sha512_update_obj, tz_sha512_update);

STATIC mp_obj_t tz_sha512_digest(mp_obj_t self_in) {
    tz_sha512_obj_t *self = MP_OBJ_TO_PTR(self_in);
    uint8_t out[SHA512_DIGEST_LENGTH];
    sha512_Final(&self->ctx, out);
    return bytes_from(out, sizeof(out));
}
STATIC MP_DEFINE_CONST_FUN_OBJ_1(tz_sha512_digest_obj, tz_sha512_digest);

STATIC mp_obj_t tz_sha512_make_new(const mp_obj_type_t *type, size_t n_args,
                                   size_t n_kw, const mp_obj_t *args) {
    mp_arg_check_num(n_args, n_kw, 0, 1, false);
    tz_sha512_obj_t *o = m_new_obj(tz_sha512_obj_t);
    o->base.type = type;
    sha512_Init(&o->ctx);
    if(n_args == 1) {
        GET_BUF(bi, args[0], MP_BUFFER_READ);
        sha512_Update(&o->ctx, bi.buf, bi.len);
    }
    return MP_OBJ_FROM_PTR(o);
}

STATIC const mp_rom_map_elem_t tz_sha512_locals_table[] = {
    { MP_ROM_QSTR(MP_QSTR_update), MP_ROM_PTR(&tz_sha512_update_obj) },
    { MP_ROM_QSTR(MP_QSTR_digest), MP_ROM_PTR(&tz_sha512_digest_obj) },
};
STATIC MP_DEFINE_CONST_DICT(tz_sha512_locals, tz_sha512_locals_table);

const mp_obj_type_t tz_sha512_type = {
    { &mp_type_type },
    .name = MP_QSTR_sha512,
    .make_new = tz_sha512_make_new,
    .locals_dict = (mp_obj_dict_t *)&tz_sha512_locals,
};

STATIC const mp_rom_map_elem_t mp_module_hash_globals_table[] = {
    { MP_ROM_QSTR(MP_QSTR___name__), MP_ROM_QSTR(MP_QSTR_hash) },
    { MP_ROM_QSTR(MP_QSTR_sha256s), MP_ROM_PTR(&tz_sha256s_obj) },
    { MP_ROM_QSTR(MP_QSTR_sha256d), MP_ROM_PTR(&tz_sha256d_obj) },
    { MP_ROM_QSTR(MP_QSTR_sha256t), MP_ROM_PTR(&tz_sha256t_obj) },
    { MP_ROM_QSTR(MP_QSTR_ripemd160), MP_ROM_PTR(&tz_ripemd160_obj) },
    { MP_ROM_QSTR(MP_QSTR_hash160), MP_ROM_PTR(&tz_hash160_obj) },
    { MP_ROM_QSTR(MP_QSTR_pbkdf2_sha512), MP_ROM_PTR(&tz_pbkdf2_sha512_obj) },
    { MP_ROM_QSTR(MP_QSTR_sha512), MP_ROM_PTR(&tz_sha512_type) },
};
STATIC MP_DEFINE_CONST_DICT(mp_module_hash_globals, mp_module_hash_globals_table);
const mp_obj_module_t mp_module_hash = {
    .base = { &mp_type_module },
    .globals = (mp_obj_dict_t *)&mp_module_hash_globals,
};

// ===========================================================================
// ngu.hmac
// ===========================================================================

STATIC mp_obj_t tz_hmac_sha256(mp_obj_t key_in, mp_obj_t msg_in) {
    GET_BUF(key, key_in, MP_BUFFER_READ);
    GET_BUF(msg, msg_in, MP_BUFFER_READ);
    uint8_t out[SHA256_DIGEST_LENGTH];
    hmac_sha256(key.buf, key.len, msg.buf, msg.len, out);
    return bytes_from(out, sizeof(out));
}
STATIC MP_DEFINE_CONST_FUN_OBJ_2(tz_hmac_sha256_obj, tz_hmac_sha256);

STATIC mp_obj_t tz_hmac_sha512(mp_obj_t key_in, mp_obj_t msg_in) {
    GET_BUF(key, key_in, MP_BUFFER_READ);
    GET_BUF(msg, msg_in, MP_BUFFER_READ);
    uint8_t out[SHA512_DIGEST_LENGTH];
    hmac_sha512(key.buf, key.len, msg.buf, msg.len, out);
    return bytes_from(out, sizeof(out));
}
STATIC MP_DEFINE_CONST_FUN_OBJ_2(tz_hmac_sha512_obj, tz_hmac_sha512);

// trezor-crypto has raw SHA1 but no HMAC-SHA1, so build it here from RFC 2104.
// Needed by shared/users.py for TOTP (RFC 6238 mandates HMAC-SHA1).
#define SHA1_BLOCK 64
STATIC mp_obj_t tz_hmac_sha1(mp_obj_t key_in, mp_obj_t msg_in) {
    GET_BUF(key, key_in, MP_BUFFER_READ);
    GET_BUF(msg, msg_in, MP_BUFFER_READ);

    uint8_t k[SHA1_BLOCK] = {0};
    if(key.len > SHA1_BLOCK) {
        sha1_Raw(key.buf, key.len, k);          // long keys are hashed down
    } else {
        memcpy(k, key.buf, key.len);
    }

    uint8_t pad[SHA1_BLOCK];
    uint8_t inner[SHA1_DIGEST_LENGTH];
    SHA1_CTX ctx;

    for(int i = 0; i < SHA1_BLOCK; i++) pad[i] = k[i] ^ 0x36;
    sha1_Init(&ctx);
    sha1_Update(&ctx, pad, sizeof(pad));
    sha1_Update(&ctx, msg.buf, msg.len);
    sha1_Final(&ctx, inner);

    for(int i = 0; i < SHA1_BLOCK; i++) pad[i] = k[i] ^ 0x5c;
    uint8_t out[SHA1_DIGEST_LENGTH];
    sha1_Init(&ctx);
    sha1_Update(&ctx, pad, sizeof(pad));
    sha1_Update(&ctx, inner, sizeof(inner));
    sha1_Final(&ctx, out);

    memzero(k, sizeof(k));
    memzero(pad, sizeof(pad));
    return bytes_from(out, sizeof(out));
}
STATIC MP_DEFINE_CONST_FUN_OBJ_2(tz_hmac_sha1_obj, tz_hmac_sha1);

STATIC const mp_rom_map_elem_t mp_module_hmac_globals_table[] = {
    { MP_ROM_QSTR(MP_QSTR___name__), MP_ROM_QSTR(MP_QSTR_hmac) },
    { MP_ROM_QSTR(MP_QSTR_hmac_sha256), MP_ROM_PTR(&tz_hmac_sha256_obj) },
    { MP_ROM_QSTR(MP_QSTR_hmac_sha512), MP_ROM_PTR(&tz_hmac_sha512_obj) },
    { MP_ROM_QSTR(MP_QSTR_hmac_sha1), MP_ROM_PTR(&tz_hmac_sha1_obj) },
};
STATIC MP_DEFINE_CONST_DICT(mp_module_hmac_globals, mp_module_hmac_globals_table);
const mp_obj_module_t mp_module_hmac = {
    .base = { &mp_type_module },
    .globals = (mp_obj_dict_t *)&mp_module_hmac_globals,
};

// ===========================================================================
// ngu.random
// ===========================================================================

STATIC mp_obj_t tz_random_bytes(mp_obj_t count_in) {
    mp_int_t count = mp_obj_get_int(count_in);
    if(count > 4096) mp_raise_ValueError(MP_ERROR_TEXT("too many"));
    if(count < 0) mp_raise_ValueError(MP_ERROR_TEXT("negative"));

    vstr_t v;
    vstr_init_len(&v, count);
    random_buffer((uint8_t *)v.buf, count);
    return mp_obj_new_str_from_vstr(&mp_type_bytes, &v);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_1(tz_random_bytes_obj, tz_random_bytes);

STATIC mp_obj_t tz_random_uint32(void) {
    uint32_t rv;
    random_buffer((uint8_t *)&rv, sizeof(rv));
    return mp_obj_new_int_from_uint(rv);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_0(tz_random_uint32_obj, tz_random_uint32);

STATIC mp_obj_t tz_random_uniform(mp_obj_t mx_in) {
    mp_int_t mx = mp_obj_get_int_truncated(mx_in);
    if(mx <= 1) return mp_obj_new_int_from_uint(0);
    return mp_obj_new_int_from_uint(random_uniform((uint32_t)mx));
}
STATIC MP_DEFINE_CONST_FUN_OBJ_1(tz_random_uniform_obj, tz_random_uniform);

// DIVERGENCE: in libngu this overwrote yasmarang_pad -- i.e. it *replaced* the
// state of the software generator that was (accidentally) the only entropy
// source. Here the source is the kernel CSPRNG, which a caller-supplied 32-bit
// value can neither improve nor degrade, so this is intentionally a no-op.
// Kept because shared/mk4.py:rng_seeding() calls it.
STATIC mp_obj_t tz_random_reseed(mp_obj_t arg) {
    (void)arg;
    return mp_const_none;
}
STATIC MP_DEFINE_CONST_FUN_OBJ_1(tz_random_reseed_obj, tz_random_reseed);

STATIC const mp_rom_map_elem_t mp_module_random_globals_table[] = {
    { MP_ROM_QSTR(MP_QSTR___name__), MP_ROM_QSTR(MP_QSTR_random) },
    { MP_ROM_QSTR(MP_QSTR_bytes), MP_ROM_PTR(&tz_random_bytes_obj) },
    { MP_ROM_QSTR(MP_QSTR_uint32), MP_ROM_PTR(&tz_random_uint32_obj) },
    { MP_ROM_QSTR(MP_QSTR_uniform), MP_ROM_PTR(&tz_random_uniform_obj) },
    { MP_ROM_QSTR(MP_QSTR_reseed), MP_ROM_PTR(&tz_random_reseed_obj) },
};
STATIC MP_DEFINE_CONST_DICT(mp_module_random_globals, mp_module_random_globals_table);
const mp_obj_module_t mp_module_random = {
    .base = { &mp_type_module },
    .globals = (mp_obj_dict_t *)&mp_module_random_globals,
};

// ===========================================================================
// ngu -- top level
// ===========================================================================

extern const mp_obj_module_t mp_module_codecs;
extern const mp_obj_module_t mp_module_hdnode;
extern const mp_obj_module_t mp_module_secp256k1;
extern const mp_obj_module_t mp_module_aes;

STATIC const mp_rom_map_elem_t mp_module_ngu_globals_table[] = {
    { MP_ROM_QSTR(MP_QSTR___name__), MP_ROM_QSTR(MP_QSTR_ngu) },
    { MP_ROM_QSTR(MP_QSTR_hash), MP_ROM_PTR(&mp_module_hash) },
    { MP_ROM_QSTR(MP_QSTR_hmac), MP_ROM_PTR(&mp_module_hmac) },
    { MP_ROM_QSTR(MP_QSTR_random), MP_ROM_PTR(&mp_module_random) },
    { MP_ROM_QSTR(MP_QSTR_codecs), MP_ROM_PTR(&mp_module_codecs) },
    { MP_ROM_QSTR(MP_QSTR_hdnode), MP_ROM_PTR(&mp_module_hdnode) },
    { MP_ROM_QSTR(MP_QSTR_secp256k1), MP_ROM_PTR(&mp_module_secp256k1) },
    { MP_ROM_QSTR(MP_QSTR_aes), MP_ROM_PTR(&mp_module_aes) },
};
STATIC MP_DEFINE_CONST_DICT(mp_module_ngu_globals, mp_module_ngu_globals_table);

const mp_obj_module_t mp_module_ngu = {
    .base = { &mp_type_module },
    .globals = (mp_obj_dict_t *)&mp_module_ngu_globals,
};

MP_REGISTER_MODULE(MP_QSTR_ngu, mp_module_ngu, 1);

// EOF
