//
// mod_secp256k1_tz.c -- `ngu.secp256k1` submodule, backed by trezor-crypto's
// PURE-C ECDSA (ecdsa.c + bignum.c + curves.c). No libsecp256k1.
//
// Drop-in for libngu/ngu/k1.c, minus the parts the firmware never calls
// (sign_schnorr, verify_schnorr, the whole xonly_pubkey type).
//
// - sign, pubkey recovery from sig
// - the famous 256-bit curve only
// - assume all signatures include recid for pubkey recovery (65 bytes)
//
#include "py/obj.h"
#include "py/runtime.h"
#include <string.h>

#include "ecdsa.h"
#include "secp256k1.h"
#include "bignum.h"
#include "sha2.h"
#include "rand.h"
#include "memzero.h"

#if MICROPY_ENABLE_DYNRUNTIME
#error "Static Only"
#endif

// ---------------------------------------------------------------------------
// helpers (same pattern as modngu_tz.c; redeclared static per translation unit)
// ---------------------------------------------------------------------------
STATIC mp_obj_t bytes_from(const uint8_t *p, size_t len) {
    vstr_t v;
    vstr_init_len(&v, len);
    memcpy(v.buf, p, len);
    return mp_obj_new_str_from_vstr(&mp_type_bytes, &v);
}

#define GET_BUF(dst, obj, mode) \
    mp_buffer_info_t dst; mp_get_buffer_raise(obj, &dst, mode)

// ---------------------------------------------------------------------------
// objects
//
// libsecp256k1's opaque secp256k1_pubkey / _recoverable_signature blobs have no
// equivalent here, so pubkeys are held in the canonical uncompressed form and
// signatures as raw r||s plus the recovery id.
// ---------------------------------------------------------------------------
typedef struct {
    mp_obj_base_t   base;
    uint8_t         pub65[65];      // 0x04 || x || y
} mp_obj_pubkey_t;

typedef struct {
    mp_obj_base_t   base;
    uint8_t         rs[64];         // r || s, big endian
    int             recid;          // 0..3
} mp_obj_sig_t;

typedef struct {
    mp_obj_base_t   base;
    uint8_t         privkey[32];
    uint8_t         pub65[65];
} mp_obj_keypair_t;

STATIC const mp_obj_type_t s_pubkey_type;
STATIC const mp_obj_type_t s_sig_type;
STATIC const mp_obj_type_t s_keypair_type;

// Validate a 33- or 65-byte pubkey and normalise to uncompressed. The length
// check matters: trezor's ecdsa_read_pubkey() trusts the prefix byte and would
// read 65 bytes out of a shorter buffer.
STATIC void parse_pub65(const uint8_t *p, size_t len, uint8_t out65[65]) {
    bool len_ok = ((len == 33) && ((p[0] == 0x02) || (p[0] == 0x03)))
                    || ((len == 65) && (p[0] == 0x04));

    if(!len_ok || !ecdsa_uncompress_pubkey(&secp256k1, p, out65)) {
        mp_raise_ValueError(MP_ERROR_TEXT("secp256k1_ec_pubkey_parse"));
    }
}

// DIVERGENCE: there is no context object in the pure-C backend, so there is
// nothing to re-randomize. Kept as a no-op because shared/psbt.py calls it.
STATIC mp_obj_t s_ctx_rnd(void) {
    return mp_const_none;
}
STATIC MP_DEFINE_CONST_FUN_OBJ_0(s_ctx_rnd_obj, s_ctx_rnd);

// Constructor for signature
STATIC mp_obj_t s_sig_make_new(const mp_obj_type_t *type, size_t n_args,
                               size_t n_kw, const mp_obj_t *args) {
    mp_arg_check_num(n_args, n_kw, 1, 1, false);

    GET_BUF(inp, args[0], MP_BUFFER_READ);
    const uint8_t *bi = (const uint8_t *)inp.buf;

    // expect raw recid+32+32 bytes
    if(inp.len != 65) {
        mp_raise_ValueError(MP_ERROR_TEXT("sig len != 65"));
    }

    // reject r/s >= group order, as libsecp256k1's parse_compact did
    bignum256 t = {0};
    for(int off = 1; off <= 33; off += 32) {
        bn_read_be(&bi[off], &t);
        if(!bn_is_less(&t, &secp256k1.order)) {
            mp_raise_ValueError(MP_ERROR_TEXT("parse sig"));
        }
    }

    mp_obj_sig_t *o = m_new_obj(mp_obj_sig_t);
    o->base.type = type;

    // in bitcoin world, first byte encodes recid
    o->recid = (bi[0] - 27) & 0x3;
    memcpy(o->rs, &bi[1], 64);

    return MP_OBJ_FROM_PTR(o);
}

// Constructor for pubkey
STATIC mp_obj_t s_pubkey_make_new(const mp_obj_type_t *type, size_t n_args,
                                  size_t n_kw, const mp_obj_t *args) {
    mp_arg_check_num(n_args, n_kw, 1, 1, false);

    GET_BUF(inp, args[0], MP_BUFFER_READ);

    mp_obj_pubkey_t *o = m_new_obj(mp_obj_pubkey_t);
    o->base.type = type;

    parse_pub65(inp.buf, inp.len, o->pub65);

    return MP_OBJ_FROM_PTR(o);
}

// output pubkey
STATIC mp_obj_t s_pubkey_to_bytes(size_t n_args, const mp_obj_t *args) {
    mp_obj_pubkey_t *self = MP_OBJ_TO_PTR(args[0]);

    // default: compressed, but can pass in true to get uncompressed
    if((n_args > 1) && mp_obj_is_true(args[1])) {
        return bytes_from(self->pub65, 65);
    }

    uint8_t comp[33];
    comp[0] = 0x02 | (self->pub65[64] & 1);
    memcpy(comp + 1, self->pub65 + 1, 32);

    return bytes_from(comp, sizeof(comp));
}
STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(s_pubkey_to_bytes_obj, 1, 2, s_pubkey_to_bytes);

// output signature as 65 bytes
STATIC mp_obj_t s_sig_to_bytes(mp_obj_t self_in) {
    mp_obj_sig_t *self = MP_OBJ_TO_PTR(self_in);

    uint8_t out[65];

    // first byte is bitcoin-specific rec id; always the "compressed" flavour
    out[0] = 27 + self->recid + 4;
    memcpy(&out[1], self->rs, 64);

    return bytes_from(out, sizeof(out));
}
STATIC MP_DEFINE_CONST_FUN_OBJ_1(s_sig_to_bytes_obj, s_sig_to_bytes);

// verify sig (and recover pubkey)
STATIC mp_obj_t s_sig_verify_recover(mp_obj_t self_in, mp_obj_t digest_in) {
    mp_obj_sig_t *self = MP_OBJ_TO_PTR(self_in);

    GET_BUF(digest, digest_in, MP_BUFFER_READ);
    if(digest.len != 32) {
        mp_raise_ValueError(MP_ERROR_TEXT("md len != 32"));
    }

    mp_obj_pubkey_t *rv = m_new_obj(mp_obj_pubkey_t);
    rv->base.type = &s_pubkey_type;

    // trezor returns 0 on success
    if(ecdsa_recover_pub_from_sig(&secp256k1, rv->pub65, self->rs,
                                    digest.buf, self->recid) != 0) {
        mp_raise_ValueError(MP_ERROR_TEXT("verify/recover sig"));
    }

    return MP_OBJ_FROM_PTR(rv);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_2(s_sig_verify_recover_obj, s_sig_verify_recover);

// ---------------------------------------------------------------------------
// signing
//
// libngu passed `counter` to libsecp256k1's RFC6979 as extra nonce data, and
// shared/psbt.py's ecdsa_grind_sign loops counter=0,1,2... until sig[1] < 0x80
// to obtain a low-R signature.
//
// trezor's stock ecdsa_sign_digest() has no extra-nonce-data hook, so
// tc_ecdsa_sign_digest_ex() was added (see the COLDCARD-ADDED hunks in
// crypto/ecdsa.c and crypto/rfc6979.c). It threads 32 bytes of extra entropy
// into the HMAC-DRBG seed as priv||hash||extra -- the same layout libsecp256k1
// uses for key32||msg32||data32.
//
// Result: signatures are byte-identical to the libngu build for every counter
// value, verified by external/c-modules-trezor/difftest.py. No divergence here.

STATIC mp_obj_t s_sign(mp_obj_t privkey_in, mp_obj_t digest_in, mp_obj_t counter_in) {
    GET_BUF(digest, digest_in, MP_BUFFER_READ);
    if(digest.len != 32) {
        mp_raise_ValueError(MP_ERROR_TEXT("md len != 32"));
    }

    const uint8_t *pk;
    if(mp_obj_get_type(privkey_in) == &s_keypair_type) {
        mp_obj_keypair_t *keypair = MP_OBJ_TO_PTR(privkey_in);
        pk = keypair->privkey;
    } else {
        // typical: raw privkey
        GET_BUF(privkey, privkey_in, MP_BUFFER_READ);
        if(privkey.len != 32) {
            mp_raise_ValueError(MP_ERROR_TEXT("privkey len != 32"));
        }
        pk = privkey.buf;
    }

    int counter = mp_obj_get_int_truncated(counter_in);
    if(counter < 0) counter = 0;

    mp_obj_sig_t *rv = m_new_obj(mp_obj_sig_t);
    rv->base.type = &s_sig_type;

    // `counter` is extra RFC6979 nonce entropy, encoded exactly as libngu did
    // (see its k1.c): 32 bytes, counter in the first host-endian word, rest
    // zero, and NULL when counter is 0. With init_rfc6979_ex() threading this
    // into the DRBG seed the same way libsecp256k1 does, signatures are
    // byte-identical to the libngu build for every counter value.
    uint32_t nonce_data[8] = { (uint32_t)counter, 0, };
    const uint8_t *nonce_ptr = counter ? (const uint8_t *)nonce_data : NULL;

    uint8_t pby = 0;
    int x = tc_ecdsa_sign_digest_ex(&secp256k1, pk, digest.buf, rv->rs, &pby,
                                    NULL, nonce_ptr);
    if(x != 0) {
        mp_raise_ValueError(MP_ERROR_TEXT("ecdsa_sign_digest"));
    }

    rv->recid = pby;

    return MP_OBJ_FROM_PTR(rv);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_3(s_sign_obj, s_sign);

// KEY PAIRS (private key, with public key computed)

// Constructor for keypair
STATIC mp_obj_t s_keypair_make_new(const mp_obj_type_t *type, size_t n_args,
                                   size_t n_kw, const mp_obj_t *args) {
    mp_arg_check_num(n_args, n_kw, 0, 1, false);

    mp_obj_keypair_t *o = m_new_obj(mp_obj_keypair_t);
    o->base.type = type;

    if(n_args == 0) {
        // pick random key
        random_buffer(o->privkey, 32);
    } else {
        GET_BUF(inp, args[0], MP_BUFFER_READ);
        if(inp.len != 32) {
            mp_raise_ValueError(MP_ERROR_TEXT("privkey len != 32"));
        }
        memcpy(o->privkey, inp.buf, 32);
    }

    // always derive the pubkey from the secret; this also rejects a secret that
    // is zero or >= the group order, which shared/wif.py relies on. trezor
    // returns 0 on success.
    int x = ecdsa_get_public_key65(&secp256k1, o->privkey, o->pub65);

    if((x != 0) && (n_args == 0)) {
        random_buffer(o->privkey, 32);
        x = ecdsa_get_public_key65(&secp256k1, o->privkey, o->pub65);
        // single retry only, because no-one is that unlucky
    }
    if(x != 0) {
        mp_raise_ValueError(MP_ERROR_TEXT("secp256k1_keypair_create"));
    }

    return MP_OBJ_FROM_PTR(o);
}

// keypair METHODS

STATIC mp_obj_t s_keypair_privkey(mp_obj_t self_in) {
    mp_obj_keypair_t *self = MP_OBJ_TO_PTR(self_in);

    return bytes_from(self->privkey, 32);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_1(s_keypair_privkey_obj, s_keypair_privkey);

STATIC mp_obj_t s_keypair_pubkey(mp_obj_t self_in) {
    mp_obj_keypair_t *self = MP_OBJ_TO_PTR(self_in);

    // already computed at construction
    mp_obj_pubkey_t *rv = m_new_obj(mp_obj_pubkey_t);
    rv->base.type = &s_pubkey_type;
    memcpy(rv->pub65, self->pub65, 65);

    return MP_OBJ_FROM_PTR(rv);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_1(s_keypair_pubkey_obj, s_keypair_pubkey);

// returns sha256(x||y) of privkey * other_pubkey_point -- NOT raw ECDH.
// This is libngu's _my_ecdh_hash, which libsecp256k1 called as the ecdh hash
// function; trezor's ecdh_multiply just hands back the raw point, so the
// sha256 is applied here. Used for pairing/session keys in backups.py,
// teleport.py and usb.py, so it must stay bit-exact.
STATIC mp_obj_t s_keypair_ecdh_multiply(mp_obj_t self_in, mp_obj_t other_point_in) {
    mp_obj_keypair_t *self = MP_OBJ_TO_PTR(self_in);

    GET_BUF(inp, other_point_in, MP_BUFFER_READ);

    uint8_t other[65];
    parse_pub65(inp.buf, inp.len, other);

    uint8_t sess[65];
    if(ecdh_multiply(&secp256k1, self->privkey, other, sess) != 0) {
        mp_raise_ValueError(MP_ERROR_TEXT("secp256k1_ecdh"));
    }

    // sess is 0x04 || x || y -- hash the 64 bytes of x||y
    uint8_t out[SHA256_DIGEST_LENGTH];
    sha256_Raw(&sess[1], 64, out);
    memzero(sess, sizeof(sess));

    mp_obj_t rv = bytes_from(out, sizeof(out));
    memzero(out, sizeof(out));
    return rv;
}
STATIC MP_DEFINE_CONST_FUN_OBJ_2(s_keypair_ecdh_multiply_obj, s_keypair_ecdh_multiply);

// sigs and what you can do with them
STATIC const mp_rom_map_elem_t s_sig_locals_dict_table[] = {
    { MP_ROM_QSTR(MP_QSTR_to_bytes), MP_ROM_PTR(&s_sig_to_bytes_obj) },
    { MP_ROM_QSTR(MP_QSTR_verify_recover), MP_ROM_PTR(&s_sig_verify_recover_obj) },
};
STATIC MP_DEFINE_CONST_DICT(s_sig_locals_dict, s_sig_locals_dict_table);

STATIC const mp_obj_type_t s_sig_type = {
    { &mp_type_type },
    .name = MP_QSTR_secp256k1_sig,
    .make_new = s_sig_make_new,
    .locals_dict = (void *)&s_sig_locals_dict,
};

// pubkeys and what you can do with them
STATIC const mp_rom_map_elem_t s_pubkey_locals_dict_table[] = {
    { MP_ROM_QSTR(MP_QSTR_to_bytes), MP_ROM_PTR(&s_pubkey_to_bytes_obj) },
};
STATIC MP_DEFINE_CONST_DICT(s_pubkey_locals_dict, s_pubkey_locals_dict_table);

STATIC const mp_obj_type_t s_pubkey_type = {
    { &mp_type_type },
    .name = MP_QSTR_secp256k1_pubkey,
    .make_new = s_pubkey_make_new,
    .locals_dict = (void *)&s_pubkey_locals_dict,
};

// privkeys and what you can do with them
STATIC const mp_rom_map_elem_t s_keypair_locals_dict_table[] = {
    { MP_ROM_QSTR(MP_QSTR_privkey), MP_ROM_PTR(&s_keypair_privkey_obj) },
    { MP_ROM_QSTR(MP_QSTR_pubkey), MP_ROM_PTR(&s_keypair_pubkey_obj) },
    { MP_ROM_QSTR(MP_QSTR_ecdh_multiply), MP_ROM_PTR(&s_keypair_ecdh_multiply_obj) },
};
STATIC MP_DEFINE_CONST_DICT(s_keypair_locals_dict, s_keypair_locals_dict_table);

STATIC const mp_obj_type_t s_keypair_type = {
    { &mp_type_type },
    .name = MP_QSTR_secp256k1_keypair,
    .make_new = s_keypair_make_new,
    .locals_dict = (void *)&s_keypair_locals_dict,
};

STATIC const mp_rom_map_elem_t mp_module_secp256k1_globals_table[] = {
    { MP_ROM_QSTR(MP_QSTR___name__), MP_ROM_QSTR(MP_QSTR_secp256k1) },

    { MP_ROM_QSTR(MP_QSTR_pubkey), MP_ROM_PTR(&s_pubkey_type) },
    { MP_ROM_QSTR(MP_QSTR_keypair), MP_ROM_PTR(&s_keypair_type) },
    { MP_ROM_QSTR(MP_QSTR_signature), MP_ROM_PTR(&s_sig_type) },
    { MP_ROM_QSTR(MP_QSTR_sign), MP_ROM_PTR(&s_sign_obj) },
    { MP_ROM_QSTR(MP_QSTR_ctx_rnd), MP_ROM_PTR(&s_ctx_rnd_obj) },
};
STATIC MP_DEFINE_CONST_DICT(mp_module_secp256k1_globals, mp_module_secp256k1_globals_table);

const mp_obj_module_t mp_module_secp256k1 = {
    .base = { &mp_type_module },
    .globals = (mp_obj_dict_t *)&mp_module_secp256k1_globals,
};

// EOF
