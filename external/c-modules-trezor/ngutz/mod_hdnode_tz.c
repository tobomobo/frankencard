//
// mod_hdnode_tz.c -- `ngu.hdnode` submodule, backed by trezor-crypto's bip32.c
// and its pure-C ECDSA (ecdsa.c/bignum.c/curves.c). No libsecp256k1.
//
// Drop-in for libngu/ngu/hdnode.c: same class name, same methods, same
// semantics. Backend differences are marked "DIVERGENCE:".
//
#include "py/obj.h"
#include "py/runtime.h"
#include <string.h>

#include "bip32.h"
#include "ecdsa.h"
#include "curves.h"
#include "secp256k1.h"
#include "base58.h"
#include "sha2.h"
#include "ripemd160.h"
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

STATIC uint8_t *write_be32(uint8_t *p, uint32_t v) {
    *(p++) = v >> 24;
    *(p++) = v >> 16;
    *(p++) = v >> 8;
    *(p++) = v & 0xff;
    return p;
}

STATIC uint32_t read_be32(const uint8_t *v) {
    return ((uint32_t)v[0] << 24) | ((uint32_t)v[1] << 16)
                | ((uint32_t)v[2] << 8) | (uint32_t)v[3];
}

// ---------------------------------------------------------------------------
// the object
//
// DIVERGENCE: libngu used depth=-1 as the "invalid" marker. trezor's HDNode
// has an unsigned depth, so validity is tracked in the wrapper instead. Same
// observable behaviour: every accessor raises ValueError("invalid HDNode").
// `have_private` is likewise explicit -- trezor only zeroes private_key for
// public-only nodes, which is not a distinguishable state.
// ---------------------------------------------------------------------------
typedef struct {
    mp_obj_base_t   base;
    HDNode          node;
    uint32_t        parent_fp;      // trezor's HDNode does not carry this
    bool            valid;
    bool            have_private;
} mp_obj_hdnode_t;

STATIC const mp_obj_type_t s_hdnode_type;

STATIC void raise_on_invalid(mp_obj_hdnode_t *n) {
    if(!n->valid
        || ((n->node.public_key[0] != 0x02) && (n->node.public_key[0] != 0x03))
    ) {
        mp_raise_ValueError(MP_ERROR_TEXT("invalid HDNode"));
    }
}

// derive+cache the compressed pubkey from the privkey. trezor returns 0 on ok.
STATIC void fill_pub(mp_obj_hdnode_t *self) {
    if(hdnode_fill_public_key(&self->node) != 0) {
        self->valid = false;
        mp_raise_msg(&mp_type_RuntimeError, MP_ERROR_TEXT("bip32 lottery winner"));
    }
}

STATIC void calc_hash160(mp_obj_hdnode_t *self, uint8_t out[20]) {
    uint8_t mid[SHA256_DIGEST_LENGTH];
    sha256_Raw(self->node.public_key, 33, mid);
    ripemd160(mid, sizeof(mid), out);
}

// IMPORTANT: raw big-endian read of the first 4 hash160 bytes. Callers in the
// firmware byte-swap this themselves; do not swap here.
STATIC uint32_t calc_my_fp(mp_obj_hdnode_t *self) {
    uint8_t h[20];
    calc_hash160(self, h);
    return read_be32(h);
}

// validate any-form pubkey and give back the compressed 33 bytes
STATIC void compress_pubkey(const uint8_t *p, size_t len, uint8_t out33[33]) {
    bool len_ok = ((len == 33) && ((p[0] == 0x02) || (p[0] == 0x03)))
                    || ((len == 65) && (p[0] == 0x04));

    uint8_t unc[65];
    if(!len_ok || !ecdsa_uncompress_pubkey(&secp256k1, p, unc)) {
        mp_raise_ValueError(MP_ERROR_TEXT("pubkey invalid"));
    }

    out33[0] = 0x02 | (unc[64] & 1);
    memcpy(out33 + 1, unc + 1, 32);
}

// Constructor: makes empty/invalid obj
STATIC mp_obj_t s_hdnode_make_new(const mp_obj_type_t *type, size_t n_args,
                                  size_t n_kw, const mp_obj_t *args) {
    mp_arg_check_num(n_args, n_kw, 0, 0, false);
    mp_obj_hdnode_t *o = m_new_obj_with_finaliser(mp_obj_hdnode_t);

    memset(o, 0, sizeof(mp_obj_hdnode_t));
    o->base.type = type;
    o->valid = false;

    return MP_OBJ_FROM_PTR(o);
}

// METHODS

STATIC mp_obj_t s_hdnode_copy(mp_obj_t self_in) {
    mp_obj_hdnode_t *self = MP_OBJ_TO_PTR(self_in);
    raise_on_invalid(self);         // isolates faults faster

    mp_obj_hdnode_t *rv = m_new_obj_with_finaliser(mp_obj_hdnode_t);
    *rv = *self;
    rv->base.type = &s_hdnode_type;

    return MP_OBJ_FROM_PTR(rv);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_1(s_hdnode_copy_obj, s_hdnode_copy);

STATIC mp_obj_t s_hdnode_blank(mp_obj_t self_in) {
    mp_obj_hdnode_t *self = MP_OBJ_TO_PTR(self_in);

    memzero(self, sizeof(mp_obj_hdnode_t));
    self->base.type = &s_hdnode_type;
    self->valid = false;

    return self_in;
}
STATIC MP_DEFINE_CONST_FUN_OBJ_1(s_hdnode_blank_obj, s_hdnode_blank);

STATIC mp_obj_t s_hdnode_privkey(mp_obj_t self_in) {
    mp_obj_hdnode_t *self = MP_OBJ_TO_PTR(self_in);
    raise_on_invalid(self);

    if(!self->have_private) {
        mp_raise_ValueError(MP_ERROR_TEXT("no privkey"));
    }

    return bytes_from(self->node.private_key, 32);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_1(s_hdnode_privkey_obj, s_hdnode_privkey);

STATIC mp_obj_t s_hdnode_pubkey(mp_obj_t self_in) {
    mp_obj_hdnode_t *self = MP_OBJ_TO_PTR(self_in);
    raise_on_invalid(self);

    return bytes_from(self->node.public_key, 33);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_1(s_hdnode_pubkey_obj, s_hdnode_pubkey);

STATIC mp_obj_t s_hdnode_addr_help(size_t n_args, const mp_obj_t *args) {
    mp_obj_hdnode_t *self = MP_OBJ_TO_PTR(args[0]);
    raise_on_invalid(self);

    uint8_t h160[20];
    calc_hash160(self, h160);

    // no prefix: just the raw hash160
    if(n_args < 2) {
        return bytes_from(h160, sizeof(h160));
    }

    uint8_t work[21];
    work[0] = mp_obj_get_int(args[1]);
    memcpy(&work[1], h160, 20);

    char tmp[128];
    size_t len_out = base58_encode_check(work, sizeof(work), HASHER_SHA2D,
                                            tmp, sizeof(tmp));
    if(len_out == 0) {
        mp_raise_ValueError(NULL);
    }
    return mp_obj_new_str(tmp, len_out - 1);        // len includes the NUL
}
STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(s_hdnode_addr_help_obj, 1, 2, s_hdnode_addr_help);

STATIC mp_obj_t s_hdnode_serialize(mp_obj_t self_in, mp_obj_t version_in,
                                   mp_obj_t want_private_in) {
    // output BIP32 bytes, base58check encoded
    //  version: uint32 first 4 bytes (giving xpub/Zpub/etc)
    mp_obj_hdnode_t *self = MP_OBJ_TO_PTR(self_in);
    raise_on_invalid(self);

    uint32_t version = mp_obj_get_int_truncated(version_in);
    bool want_private = mp_obj_is_true(want_private_in);

    uint8_t out[78], *p = out;

    p = write_be32(p, version);
    *(p++) = (uint8_t)self->node.depth;
    p = write_be32(p, self->parent_fp);
    p = write_be32(p, self->node.child_num);
    memcpy(p, self->node.chain_code, 32);
    p += 32;

    if(want_private) {
        if(!self->have_private) {
            mp_raise_ValueError(MP_ERROR_TEXT("no privkey"));
        }
        *(p++) = 0;
        memcpy(p, self->node.private_key, 32);
        p += 32;
    } else {
        memcpy(p, self->node.public_key, 33);
        p += 33;
    }
    (void)p;

    char tmp[150];      // max 112 based on 78 bytes in
    size_t len_out = base58_encode_check(out, sizeof(out), HASHER_SHA2D,
                                            tmp, sizeof(tmp));
    memzero(out, sizeof(out));
    if(len_out == 0) {
        memzero(tmp, sizeof(tmp));
        mp_raise_ValueError(NULL);
    }

    // tmp holds the base58check text, which for want_private is a full xprv
    // (chain code + private key). Copy it out, then wipe the stack copy.
    mp_obj_t rv = mp_obj_new_str(tmp, len_out - 1);     // len includes the NUL
    memzero(tmp, sizeof(tmp));

    return rv;
}
STATIC MP_DEFINE_CONST_FUN_OBJ_3(s_hdnode_serialize_obj, s_hdnode_serialize);

STATIC mp_obj_t s_hdnode_deserialize(mp_obj_t self_in, mp_obj_t encoded) {
    // deserialize into self, from base58; returns the version word observed
    mp_obj_hdnode_t *self = MP_OBJ_TO_PTR(self_in);

    self->valid = false;

    // DIVERGENCE: trezor's hdnode_deserialize_{public,private}() require the
    // caller to pass the expected version and reject anything else, while
    // libngu accepts ANY version and hands it back. So the base58check decode
    // and field parsing are done by hand here, exactly as libngu did.
    uint8_t raw[78];
    size_t got = base58_decode_check(mp_obj_str_get_str(encoded), HASHER_SHA2D,
                                        raw, sizeof(raw));
    // DIVERGENCE: libngu could tell "encoding error" (bad base58/checksum)
    // apart from "bad len"; trezor's decode collapses both into a 0 return.
    if(got != sizeof(raw)) {
        mp_raise_ValueError(MP_ERROR_TEXT("encoding error"));
    }

    uint32_t version = read_be32(&raw[0]);
    uint32_t depth = raw[4];
    uint32_t parent_fp = read_be32(&raw[5]);
    uint32_t child_num = read_be32(&raw[9]);
    const uint8_t *chain_code = &raw[13];
    const uint8_t *key = &raw[45];

    if(key[0] == 0x00) {
        // DIVERGENCE: an out-of-range private key is a ValueError here;
        // libngu reached secp256k1_ec_pubkey_create and raised RuntimeError.
        if(!hdnode_from_xprv(depth, child_num, chain_code, &key[1],
                                SECP256K1_NAME, &self->node)) {
            mp_raise_ValueError(MP_ERROR_TEXT("bad privkey"));
        }
        self->have_private = true;
        fill_pub(self);
    } else if((key[0] == 0x02) || (key[0] == 0x03)) {
        if(!hdnode_from_xpub(depth, child_num, chain_code, key,
                                SECP256K1_NAME, &self->node)) {
            mp_raise_ValueError(MP_ERROR_TEXT("bad pubkey"));
        }
        self->have_private = false;
    } else {
        mp_raise_ValueError(MP_ERROR_TEXT("bad pubkey"));
    }

    self->parent_fp = parent_fp;
    self->valid = true;

    memzero(raw, sizeof(raw));

    return mp_obj_new_int(version);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_2(s_hdnode_deserialize_obj, s_hdnode_deserialize);

STATIC mp_obj_t s_hdnode_from_master(mp_obj_t self_in, mp_obj_t master_secret_in) {
    mp_obj_hdnode_t *self = MP_OBJ_TO_PTR(self_in);
    GET_BUF(seed, master_secret_in, MP_BUFFER_READ);

    self->valid = false;

    // DIVERGENCE (spec-conforming, unobservable): trezor re-hashes I when the
    // seed-derived key is zero or >= order, as BIP-32 requires; libngu just
    // used it. Only differs at probability ~2^-127.
    if(!hdnode_from_seed(seed.buf, seed.len, SECP256K1_NAME, &self->node)) {
        mp_raise_ValueError(MP_ERROR_TEXT("from_master"));
    }

    self->parent_fp = 0;
    self->have_private = true;
    fill_pub(self);
    self->valid = true;

    return self_in;
}
STATIC MP_DEFINE_CONST_FUN_OBJ_2(s_hdnode_from_master_obj, s_hdnode_from_master);

STATIC mp_obj_t s_hdnode_from_chaincode_privkey(mp_obj_t self_in,
                        mp_obj_t chain_code_in, mp_obj_t privkey_in) {
    mp_obj_hdnode_t *self = MP_OBJ_TO_PTR(self_in);
    GET_BUF(cc, chain_code_in, MP_BUFFER_READ);
    GET_BUF(pk, privkey_in, MP_BUFFER_READ);

    if(cc.len != 32) mp_raise_ValueError(MP_ERROR_TEXT("chaincode len"));
    if(pk.len != 32) mp_raise_ValueError(MP_ERROR_TEXT("privkey len"));

    self->valid = false;

    // depth/child_num/parent_fp all reset to zero
    // DIVERGENCE: out-of-range privkey -> ValueError (libngu: RuntimeError).
    if(!hdnode_from_xprv(0, 0, cc.buf, pk.buf, SECP256K1_NAME, &self->node)) {
        mp_raise_ValueError(MP_ERROR_TEXT("privkey invalid"));
    }

    self->parent_fp = 0;
    self->have_private = true;
    fill_pub(self);
    self->valid = true;

    return self_in;
}
STATIC MP_DEFINE_CONST_FUN_OBJ_3(s_hdnode_from_chaincode_privkey_obj, s_hdnode_from_chaincode_privkey);

STATIC mp_obj_t s_hdnode_from_chaincode_pubkey(mp_obj_t self_in,
                        mp_obj_t chain_code_in, mp_obj_t pubkey_in) {
    mp_obj_hdnode_t *self = MP_OBJ_TO_PTR(self_in);
    GET_BUF(cc, chain_code_in, MP_BUFFER_READ);
    GET_BUF(pk, pubkey_in, MP_BUFFER_READ);

    if(cc.len != 32) mp_raise_ValueError(MP_ERROR_TEXT("chaincode len"));

    uint8_t comp[33];
    compress_pubkey(pk.buf, pk.len, comp);

    self->valid = false;

    if(!hdnode_from_xpub(0, 0, cc.buf, comp, SECP256K1_NAME, &self->node)) {
        mp_raise_ValueError(MP_ERROR_TEXT("pubkey invalid"));
    }

    self->parent_fp = 0;
    self->have_private = false;
    self->valid = true;

    return self_in;
}
STATIC MP_DEFINE_CONST_FUN_OBJ_3(s_hdnode_from_chaincode_pubkey_obj, s_hdnode_from_chaincode_pubkey);

STATIC mp_obj_t s_hdnode_derive(mp_obj_t self_in, mp_obj_t next_child_in,
                                mp_obj_t hard_in) {
    mp_obj_hdnode_t *self = MP_OBJ_TO_PTR(self_in);
    raise_on_invalid(self);

    uint32_t next_child = mp_obj_get_int_truncated(next_child_in);
    bool hard = mp_obj_is_true(hard_in);
    if(hard) next_child |= 0x80000000;

    if(hard && !self->have_private) {
        mp_raise_TypeError(MP_ERROR_TEXT("hard deriv on pubkey"));
    }

    // fingerprint of the PRE-derivation node
    uint32_t parent_fp = calc_my_fp(self);

    // these two both bump depth and set child_num; they return 1 on success
    int ok;
    if(self->have_private) {
        ok = hdnode_private_ckd(&self->node, next_child);
    } else {
        ok = hdnode_public_ckd(&self->node, next_child);
    }
    if(!ok) {
        self->valid = false;
        mp_raise_ValueError(MP_ERROR_TEXT("bip32 lottery won"));
    }

    if(self->have_private) {
        fill_pub(self);         // private_ckd invalidates the cached pubkey
    }

    self->parent_fp = parent_fp;

    return self_in;
}
STATIC MP_DEFINE_CONST_FUN_OBJ_3(s_hdnode_derive_obj, s_hdnode_derive);

// Accessors

STATIC mp_obj_t s_hdnode_depth(mp_obj_t self_in) {
    mp_obj_hdnode_t *self = MP_OBJ_TO_PTR(self_in);
    raise_on_invalid(self);

    return MP_OBJ_NEW_SMALL_INT(self->node.depth);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_1(s_hdnode_depth_obj, s_hdnode_depth);

STATIC mp_obj_t s_hdnode_parent_fp(mp_obj_t self_in) {
    mp_obj_hdnode_t *self = MP_OBJ_TO_PTR(self_in);
    raise_on_invalid(self);

    return mp_obj_new_int_from_uint(self->parent_fp);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_1(s_hdnode_parent_fp_obj, s_hdnode_parent_fp);

STATIC mp_obj_t s_hdnode_my_fp(mp_obj_t self_in) {
    mp_obj_hdnode_t *self = MP_OBJ_TO_PTR(self_in);
    raise_on_invalid(self);

    return mp_obj_new_int_from_uint(calc_my_fp(self));
}
STATIC MP_DEFINE_CONST_FUN_OBJ_1(s_hdnode_my_fp_obj, s_hdnode_my_fp);

STATIC mp_obj_t s_hdnode_child_number(mp_obj_t self_in) {
    mp_obj_hdnode_t *self = MP_OBJ_TO_PTR(self_in);
    raise_on_invalid(self);

    const mp_obj_t rv[2] = {
        MP_OBJ_NEW_SMALL_INT(self->node.child_num & 0x7fffffff),
        (self->node.child_num & 0x80000000) ? mp_const_true : mp_const_false,
    };
    return mp_obj_new_tuple(2, rv);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_1(s_hdnode_child_number_obj, s_hdnode_child_number);

STATIC mp_obj_t s_hdnode_chain_code(mp_obj_t self_in) {
    mp_obj_hdnode_t *self = MP_OBJ_TO_PTR(self_in);
    raise_on_invalid(self);

    return bytes_from(self->node.chain_code, 32);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_1(s_hdnode_chain_code_obj, s_hdnode_chain_code);

// member vars
STATIC const mp_rom_map_elem_t s_hdnode_locals_dict_table[] = {
    { MP_ROM_QSTR(MP_QSTR_privkey), MP_ROM_PTR(&s_hdnode_privkey_obj) },
    { MP_ROM_QSTR(MP_QSTR_pubkey), MP_ROM_PTR(&s_hdnode_pubkey_obj) },
    { MP_ROM_QSTR(MP_QSTR_serialize), MP_ROM_PTR(&s_hdnode_serialize_obj) },
    { MP_ROM_QSTR(MP_QSTR_deserialize), MP_ROM_PTR(&s_hdnode_deserialize_obj) },
    { MP_ROM_QSTR(MP_QSTR_from_master), MP_ROM_PTR(&s_hdnode_from_master_obj) },
    { MP_ROM_QSTR(MP_QSTR_from_chaincode_privkey), MP_ROM_PTR(&s_hdnode_from_chaincode_privkey_obj) },
    { MP_ROM_QSTR(MP_QSTR_from_chaincode_pubkey), MP_ROM_PTR(&s_hdnode_from_chaincode_pubkey_obj) },
    { MP_ROM_QSTR(MP_QSTR_derive), MP_ROM_PTR(&s_hdnode_derive_obj) },
    { MP_ROM_QSTR(MP_QSTR_addr_help), MP_ROM_PTR(&s_hdnode_addr_help_obj) },

    { MP_ROM_QSTR(MP_QSTR_depth), MP_ROM_PTR(&s_hdnode_depth_obj) },
    { MP_ROM_QSTR(MP_QSTR_child_number), MP_ROM_PTR(&s_hdnode_child_number_obj) },
    { MP_ROM_QSTR(MP_QSTR_parent_fp), MP_ROM_PTR(&s_hdnode_parent_fp_obj) },
    { MP_ROM_QSTR(MP_QSTR_my_fp), MP_ROM_PTR(&s_hdnode_my_fp_obj) },
    { MP_ROM_QSTR(MP_QSTR_chain_code), MP_ROM_PTR(&s_hdnode_chain_code_obj) },

    { MP_ROM_QSTR(MP_QSTR_copy), MP_ROM_PTR(&s_hdnode_copy_obj) },

    { MP_ROM_QSTR(MP_QSTR_blank), MP_ROM_PTR(&s_hdnode_blank_obj) },
    { MP_ROM_QSTR(MP_QSTR___del__), MP_ROM_PTR(&s_hdnode_blank_obj) },
};
STATIC MP_DEFINE_CONST_DICT(s_hdnode_locals_dict, s_hdnode_locals_dict_table);

// class: HDNode
STATIC const mp_obj_type_t s_hdnode_type = {
    { &mp_type_type },
    .name = MP_QSTR_HDNode,
    .make_new = s_hdnode_make_new,
    .locals_dict = (void *)&s_hdnode_locals_dict,
};

STATIC const mp_rom_map_elem_t mp_module_hdnode_globals_table[] = {
    { MP_ROM_QSTR(MP_QSTR___name__), MP_ROM_QSTR(MP_QSTR_hdnode) },
    { MP_ROM_QSTR(MP_QSTR_HDNode), MP_ROM_PTR(&s_hdnode_type) },
};
STATIC MP_DEFINE_CONST_DICT(mp_module_hdnode_globals, mp_module_hdnode_globals_table);

const mp_obj_module_t mp_module_hdnode = {
    .base = { &mp_type_module },
    .globals = (mp_obj_dict_t *)&mp_module_hdnode_globals,
};

// EOF
