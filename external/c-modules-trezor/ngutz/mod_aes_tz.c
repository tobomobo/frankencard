//
// mod_aes_tz.c -- the `ngu.aes` submodule, backed by trezor-crypto.
//
// Replaces libngu's aes.c (cifra) with Gladman's AES from trezor-crypto.
// Basic AES, not PEP-272: CBC and CTR only, no padding.
//
// Backend differences vs libngu are called out with "DIVERGENCE:" comments.
//
#include "py/obj.h"
#include "py/runtime.h"
#include <string.h>

#include "aes/aes.h"
#include "memzero.h"

#if MICROPY_ENABLE_DYNRUNTIME
#error "Static Only"
#endif

// same helper as modngu_tz.c (static, so a copy per translation unit)
#define GET_BUF(dst, obj, mode) \
    mp_buffer_info_t dst; mp_get_buffer_raise(obj, &dst, mode)

// CTR keystream state lives entirely in these two members: aes_ctr_crypt()
// keeps the counter block in cbuf and the offset into the current keystream
// block in ctx.inf.b[2]. So a flat struct copy is a complete clone, and
// sequential .cipher() calls of any length continue the keystream -- same
// contract cifra's cf_ctr gave libngu.
typedef struct {
    mp_obj_base_t   base;
    aes_encrypt_ctx ctx;
    uint8_t         cbuf[AES_BLOCK_SIZE];
} mp_obj_CTR_t;

// CBC direction is fixed at construction, so only one key schedule is ever
// live; aes_cbc_{en,de}crypt() carry the chain value in iv[].
typedef struct {
    mp_obj_base_t   base;
    bool            is_encrypt;
    union {
        aes_encrypt_ctx e;
        aes_decrypt_ctx d;
    } ctx;
    uint8_t         iv[AES_BLOCK_SIZE];
} mp_obj_CBC_t;

STATIC const mp_obj_type_t s_CBC_type, s_CTR_type;

// Needs -DAES_128 -DAES_192 from micropython.mk; without them aes.h only
// declares the 256-bit schedulers.
STATIC void _aes_key(mp_obj_t key_in, void *cx, bool is_encrypt) {
    mp_buffer_info_t key;
    mp_get_buffer_raise(key_in, &key, MP_BUFFER_READ);

    AES_RETURN ok;
    switch(key.len) {
        case 16:
            ok = is_encrypt ? aes_encrypt_key128(key.buf, cx)
                            : aes_decrypt_key128(key.buf, cx);
            break;
        case 24:
            ok = is_encrypt ? aes_encrypt_key192(key.buf, cx)
                            : aes_decrypt_key192(key.buf, cx);
            break;
        case 32:
            ok = is_encrypt ? aes_encrypt_key256(key.buf, cx)
                            : aes_decrypt_key256(key.buf, cx);
            break;
        default:
            mp_raise_ValueError(NULL);
            return;                 // not reached; keeps `ok` provably set
    }
    // a failed key schedule would leave cx holding whatever was there before
    if(ok != EXIT_SUCCESS) {
        mp_raise_ValueError(MP_ERROR_TEXT("aes key schedule"));
    }
}

// ===========================================================================
// CTR
// ===========================================================================

STATIC mp_obj_t s_CTR_make_new(const mp_obj_type_t *type, size_t n_args,
                               size_t n_kw, const mp_obj_t *args) {
    // args: key, nonce?
    mp_arg_check_num(n_args, n_kw, 1, 2, false);

    mp_obj_CTR_t *o = m_new_obj_with_finaliser(mp_obj_CTR_t);
    o->base.type = type;

    _aes_key(args[0], &o->ctx, true);       // also zeroes ctx.inf, so b_pos = 0

    memset(o->cbuf, 0, AES_BLOCK_SIZE);
    if(n_args == 2) {
        GET_BUF(nonce, args[1], MP_BUFFER_READ);
        if(nonce.len != AES_BLOCK_SIZE) {
            mp_raise_ValueError(NULL);
        }
        memcpy(o->cbuf, nonce.buf, AES_BLOCK_SIZE);
    }

    return MP_OBJ_FROM_PTR(o);
}

STATIC mp_obj_t s_CTR_cipher(mp_obj_t self_in, mp_obj_t buf_in) {
    mp_obj_CTR_t *self = MP_OBJ_TO_PTR(self_in);
    GET_BUF(buf, buf_in, MP_BUFFER_READ);

    vstr_t rv;
    vstr_init_len(&rv, buf.len);

    // any size i/o works; partial blocks resume on the next call
    // vstr memory is not zeroed, so an unchecked failure here would hand
    // uninitialised heap back to Python as if it were keystream output.
    if(aes_ctr_crypt(buf.buf, (uint8_t *)rv.buf, buf.len,
                        self->cbuf, aes_ctr_cbuf_inc, &self->ctx) != EXIT_SUCCESS) {
        vstr_clear(&rv);
        mp_raise_ValueError(MP_ERROR_TEXT("aes_ctr_crypt"));
    }

    return mp_obj_new_str_from_vstr(&mp_type_bytes, &rv);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_2(s_CTR_cipher_obj, s_CTR_cipher);

STATIC mp_obj_t s_CTR_blank(mp_obj_t self_in) {
    mp_obj_CTR_t *self = MP_OBJ_TO_PTR(self_in);

    memzero(self, sizeof(mp_obj_CTR_t));
    self->base.type = &s_CTR_type;

    return self_in;
}
STATIC MP_DEFINE_CONST_FUN_OBJ_1(s_CTR_blank_obj, s_CTR_blank);

STATIC mp_obj_t s_CTR_copy(mp_obj_t self_in) {
    mp_obj_CTR_t *self = MP_OBJ_TO_PTR(self_in);

    mp_obj_CTR_t *rv = m_new_obj_with_finaliser(mp_obj_CTR_t);
    *rv = *self;
    rv->base.type = &s_CTR_type;

    return MP_OBJ_FROM_PTR(rv);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_1(s_CTR_copy_obj, s_CTR_copy);

STATIC const mp_rom_map_elem_t s_CTR_locals_dict_table[] = {
    { MP_ROM_QSTR(MP_QSTR_cipher), MP_ROM_PTR(&s_CTR_cipher_obj) },
    { MP_ROM_QSTR(MP_QSTR_blank), MP_ROM_PTR(&s_CTR_blank_obj) },
    { MP_ROM_QSTR(MP_QSTR_copy), MP_ROM_PTR(&s_CTR_copy_obj) },
    { MP_ROM_QSTR(MP_QSTR___del__), MP_ROM_PTR(&s_CTR_blank_obj) },
};
STATIC MP_DEFINE_CONST_DICT(s_CTR_locals_dict, s_CTR_locals_dict_table);

STATIC const mp_obj_type_t s_CTR_type = {
    { &mp_type_type },
    .name = MP_QSTR_CTR,
    .make_new = s_CTR_make_new,
    .locals_dict = (void *)&s_CTR_locals_dict,
};

// ===========================================================================
// CBC
// ===========================================================================

STATIC mp_obj_t s_CBC_make_new(const mp_obj_type_t *type, size_t n_args,
                               size_t n_kw, const mp_obj_t *args) {
    // args: is_encrypt, key, iv
    mp_arg_check_num(n_args, n_kw, 3, 3, false);

    mp_obj_CBC_t *o = m_new_obj_with_finaliser(mp_obj_CBC_t);
    o->base.type = type;

    o->is_encrypt = !!mp_obj_get_int_truncated(args[0]);

    _aes_key(args[1], &o->ctx, o->is_encrypt);

    GET_BUF(iv, args[2], MP_BUFFER_READ);
    if(iv.len != AES_BLOCK_SIZE) {
        mp_raise_ValueError(MP_ERROR_TEXT("iv"));
    }
    memcpy(o->iv, iv.buf, AES_BLOCK_SIZE);

    return MP_OBJ_FROM_PTR(o);
}

STATIC mp_obj_t s_CBC_cipher(mp_obj_t self_in, mp_obj_t buf_in) {
    mp_obj_CBC_t *self = MP_OBJ_TO_PTR(self_in);
    GET_BUF(buf, buf_in, MP_BUFFER_READ);

    if(buf.len % AES_BLOCK_SIZE) {          // no padding, ever
        mp_raise_ValueError(NULL);
    }

    vstr_t rv;
    vstr_init_len(&rv, buf.len);

    AES_RETURN ok;
    if(self->is_encrypt) {
        ok = aes_cbc_encrypt(buf.buf, (uint8_t *)rv.buf, buf.len, self->iv, &self->ctx.e);
    } else {
        ok = aes_cbc_decrypt(buf.buf, (uint8_t *)rv.buf, buf.len, self->iv, &self->ctx.d);
    }
    if(ok != EXIT_SUCCESS) {
        vstr_clear(&rv);            // do not return uninitialised heap
        mp_raise_ValueError(MP_ERROR_TEXT("aes_cbc"));
    }

    return mp_obj_new_str_from_vstr(&mp_type_bytes, &rv);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_2(s_CBC_cipher_obj, s_CBC_cipher);

STATIC mp_obj_t s_CBC_blank(mp_obj_t self_in) {
    mp_obj_CBC_t *self = MP_OBJ_TO_PTR(self_in);

    memzero(self, sizeof(mp_obj_CBC_t));
    self->base.type = &s_CBC_type;

    return self_in;
}
STATIC MP_DEFINE_CONST_FUN_OBJ_1(s_CBC_blank_obj, s_CBC_blank);

STATIC mp_obj_t s_CBC_copy(mp_obj_t self_in) {
    mp_obj_CBC_t *self = MP_OBJ_TO_PTR(self_in);

    mp_obj_CBC_t *rv = m_new_obj_with_finaliser(mp_obj_CBC_t);
    *rv = *self;
    rv->base.type = &s_CBC_type;

    return MP_OBJ_FROM_PTR(rv);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_1(s_CBC_copy_obj, s_CBC_copy);

STATIC const mp_rom_map_elem_t s_CBC_locals_dict_table[] = {
    { MP_ROM_QSTR(MP_QSTR_cipher), MP_ROM_PTR(&s_CBC_cipher_obj) },
    { MP_ROM_QSTR(MP_QSTR_blank), MP_ROM_PTR(&s_CBC_blank_obj) },
    { MP_ROM_QSTR(MP_QSTR_copy), MP_ROM_PTR(&s_CBC_copy_obj) },
    { MP_ROM_QSTR(MP_QSTR___del__), MP_ROM_PTR(&s_CBC_blank_obj) },
};
STATIC MP_DEFINE_CONST_DICT(s_CBC_locals_dict, s_CBC_locals_dict_table);

STATIC const mp_obj_type_t s_CBC_type = {
    { &mp_type_type },
    .name = MP_QSTR_CBC,
    .make_new = s_CBC_make_new,
    .locals_dict = (void *)&s_CBC_locals_dict,
};

// ===========================================================================

STATIC const mp_rom_map_elem_t mp_module_aes_globals_table[] = {
    { MP_ROM_QSTR(MP_QSTR___name__), MP_ROM_QSTR(MP_QSTR_aes) },

    { MP_ROM_QSTR(MP_QSTR_CTR), MP_ROM_PTR(&s_CTR_type) },
    { MP_ROM_QSTR(MP_QSTR_CBC), MP_ROM_PTR(&s_CBC_type) },
};
STATIC MP_DEFINE_CONST_DICT(mp_module_aes_globals, mp_module_aes_globals_table);

const mp_obj_module_t mp_module_aes = {
    .base = { &mp_type_module },
    .globals = (mp_obj_dict_t *)&mp_module_aes_globals,
};

// EOF
