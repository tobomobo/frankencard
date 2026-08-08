//
// mod_codecs_tz.c -- the `ngu.codecs` submodule, backed by trezor-crypto.
//
// Replaces libngu's codecs.c (Google base32 + libbase58 + bech32 reference).
// Same names, same signatures, same semantics.
//
// Backend differences vs libngu are called out with "DIVERGENCE:" comments.
//
#include "py/obj.h"
#include "py/runtime.h"
#include <string.h>

#include "base32.h"
#include "base58.h"
#include "segwit_addr.h"
#include "hasher.h"
#include "memzero.h"

#if MICROPY_ENABLE_DYNRUNTIME
#error "Static Only"
#endif

// same helpers as modngu_tz.c (static, so a copy per translation unit)
STATIC mp_obj_t bytes_from(const uint8_t *p, size_t len) {
    vstr_t v;
    vstr_init_len(&v, len);
    memcpy(v.buf, p, len);
    return mp_obj_new_str_from_vstr(&mp_type_bytes, &v);
}

#define GET_BUF(dst, obj, mode) \
    mp_buffer_info_t dst; mp_get_buffer_raise(obj, &dst, mode)

// ===========================================================================
// Base 32 -- RFC4648, no '=' padding
// ===========================================================================

// Pass trezor's own BASE32_ALPHABET_RFC4648 pointer, not an equivalent string
// literal: base32_{en,de}code_character() test that pointer for identity and
// only then use the arithmetic RFC4648 mapping. The generic strchr() fallback
// would hit the stray "89" at the tail of that (34-char) table.
#define B32_ALPHA   BASE32_ALPHABET_RFC4648

STATIC mp_obj_t tz_b32_encode(mp_obj_t arg) {
    GET_BUF(bi, arg, MP_BUFFER_READ);

    // ceil(len*8/5) chars, i.e. unpadded -- libngu's encoder emitted no '='
    // either, and BBQr/TOTP callers depend on that.
    size_t olen = base32_encoded_length(bi.len);

    vstr_t v;
    vstr_init_len(&v, olen + 1);            // trezor's encoder NUL-terminates
    if(!base32_encode(bi.buf, bi.len, v.buf, olen + 1, B32_ALPHA)) {
        mp_raise_ValueError(NULL);
    }
    v.len = olen;                           // drop the NUL

    return mp_obj_new_str_from_vstr(&mp_type_str, &v);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_1(tz_b32_encode_obj, tz_b32_encode);

STATIC mp_obj_t tz_b32_decode(mp_obj_t arg) {
    size_t slen;
    const char *s = mp_obj_str_get_data(arg, &slen);

    // This deliberately does NOT use trezor's base32_decode(): libngu's decoder
    // is lenient on purpose, and shared/teleport.py depends on it. Teleport
    // Passwords are typed in by hand, and teleport.py:227 documents that the
    // receiver "will convert '018' into 'OLB'". Rejecting those would turn a
    // successful paste into "Incorrect Teleport Password".
    //
    // Ported from external/libngu/ngu/base32.c so the accept/reject behaviour
    // and the output for every input match libngu exactly:
    //   - skip ' ', '\t', '\r', '\n' and '-' anywhere
    //   - stop at the first '='
    //   - remap mistyped '0'->'O', '1'->'L', '8'->'B'
    //   - case insensitive
    //   - a trailing partial group contributes no byte (no error)
    // buffer is never masked, so it shifts left 5 per character without bound
    // and reaches bit 31 after seven of them. libngu declared it `int`, where
    // that is signed overflow (UB); unsigned here, which is the same output on
    // every compiler either has ever been built with, minus the UB.
    uint32_t buffer = 0;
    int bits_left = 0;
    vstr_t v;
    vstr_init(&v, (slen * 5 / 8) + 1);

    for(size_t i = 0; i < slen; i++) {
        uint8_t ch = (uint8_t)s[i];

        if(ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n' || ch == '-') {
            continue;
        }
        if(ch == '=') break;

        if(ch == '0')      ch = 'O';
        else if(ch == '1') ch = 'L';
        else if(ch == '8') ch = 'B';

        if((ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z')) {
            ch = (ch & 0x1F) - 1;
        } else if(ch >= '2' && ch <= '7') {
            ch -= '2' - 26;
        } else {
            vstr_clear(&v);
            mp_raise_ValueError(NULL);
        }

        buffer = (buffer << 5) | ch;
        bits_left += 5;
        if(bits_left >= 8) {
            bits_left -= 8;
            vstr_add_byte(&v, (buffer >> bits_left) & 0xff);
        }
    }

    return mp_obj_new_str_from_vstr(&mp_type_bytes, &v);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_1(tz_b32_decode_obj, tz_b32_decode);

// ===========================================================================
// Base 58 -- always Base58Check, never with a particular prefix
// ===========================================================================

// libngu sized both working buffers at 128 bytes and raised ValueError past
// that; trezor's base58_{en,de}code_check() also refuse datalen > 128.
#define B58_MAX     128

STATIC mp_obj_t tz_b58_encode(mp_obj_t arg) {
    GET_BUF(bi, arg, MP_BUFFER_READ);

    char tmp[B58_MAX];
    size_t n = base58_encode_check(bi.buf, bi.len, HASHER_SHA2D, tmp, sizeof(tmp));
    if(n == 0) {
        mp_raise_ValueError(NULL);
    }

    return mp_obj_new_str(tmp, n - 1);      // n counts the NUL
}
STATIC MP_DEFINE_CONST_FUN_OBJ_1(tz_b58_encode_obj, tz_b58_encode);

STATIC mp_obj_t tz_b58_decode(mp_obj_t arg) {
    const char *s = mp_obj_str_get_str(arg);

    uint8_t tmp[B58_MAX];
    size_t n = base58_decode_check(s, HASHER_SHA2D, tmp, sizeof(tmp));
    if(n == 0) {
        mp_raise_ValueError(NULL);          // bad checksum, bad char, or too big
    }

    // DIVERGENCE: libngu left its stack copy behind. WIF private keys come
    // through here (shared/wif.py), so wipe it.
    mp_obj_t rv = bytes_from(tmp, n);
    memzero(tmp, sizeof(tmp));

    return rv;
}
STATIC MP_DEFINE_CONST_FUN_OBJ_1(tz_b58_decode_obj, tz_b58_decode);

// ===========================================================================
// Segwit = BECH32(m)
// ===========================================================================

// trezor's segwit_addr_encode() picks bech32 for v0 and bech32m for v1+ by
// itself, same as the libngu copy.
STATIC mp_obj_t tz_segwit_encode(mp_obj_t hrp_in, mp_obj_t witver_in, mp_obj_t prog_in) {
    const char *hrp = mp_obj_str_get_str(hrp_in);
    int witver = mp_obj_get_int_truncated(witver_in);
    GET_BUF(prog, prog_in, MP_BUFFER_READ);

    // tmp[] is libngu's size, and it cannot overflow: segwit_addr_encode()
    // rejects witprog_len > 40, and bech32_encode() returns 0 on
    // `strlen(hrp) + 7 + data_len > 90` BEFORE its first write to output. So
    // the most that is ever written is 90 characters plus the NUL.
    //
    // An earlier version capped hrp at 40 here, on the belief that
    // bech32_encode() did not bounds-check. It does. The cap only rejected
    // hrp 41..50, which libngu encodes fine -- a divergence buying nothing.
    char tmp[127];
    if(!segwit_addr_encode(tmp, hrp, witver, prog.buf, prog.len)) {
        mp_raise_ValueError(MP_ERROR_TEXT("segwit_addr_encode"));
    }

    return mp_obj_new_str(tmp, strlen(tmp));
}
STATIC MP_DEFINE_CONST_FUN_OBJ_3(tz_segwit_encode_obj, tz_segwit_encode);

STATIC mp_obj_t tz_segwit_decode(mp_obj_t addr_in) {
    const char *addr = mp_obj_str_get_str(addr_in);

    // libngu called segwit_addr_decode_detailed(), a local addition that
    // reported the observed hrp. trezor only has segwit_addr_decode(), which
    // takes the expected hrp as input -- so recover it with bech32_decode()
    // first (that is the same split-on-the-last-'1' logic, and it lowercases
    // the hrp the same way) and then hand it straight back in.
    // The 90-char guard is what trezor's segwit_addr_decode() does before its
    // own bech32_decode() call; bech32_decode() itself does not bound the
    // input, and data[] below is only sized for a legal address.
    if(strlen(addr) > 90) {
        mp_raise_ValueError(MP_ERROR_TEXT("bech32 encoding"));
    }

    char hrp[BECH32_MAX_HRP_LEN + 1] = {0};
    uint8_t data[84];
    size_t data_len = 0;
    if(bech32_decode(hrp, data, &data_len, addr) == BECH32_ENCODING_NONE) {
        mp_raise_ValueError(MP_ERROR_TEXT("bech32 encoding"));
    }

    // does the version/length/encoding checks, and re-confirms the hrp
    uint8_t prog[40];
    size_t prog_len = 0;
    int version = -1;
    if(!segwit_addr_decode(&version, prog, &prog_len, hrp, addr)) {
        mp_raise_ValueError(MP_ERROR_TEXT("bech32 encoding"));
    }

    // DIVERGENCE: libngu truncated the returned hrp to 20 bytes (char[20] +
    // strncpy(...,20), which could even come back unterminated). Full hrp here.
    mp_obj_t rv[3] = {
        mp_obj_new_str(hrp, strlen(hrp)),
        MP_OBJ_NEW_SMALL_INT(version),
        bytes_from(prog, prog_len),
    };

    return mp_obj_new_tuple(3, rv);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_1(tz_segwit_decode_obj, tz_segwit_decode);

// DIVERGENCE: libngu also exposed nip19_encode/nip19_decode (raw bech32 for
// nostr keys). Nothing in shared/ uses them, so they are not provided.

// ===========================================================================

STATIC const mp_rom_map_elem_t mp_module_codecs_globals_table[] = {
    { MP_ROM_QSTR(MP_QSTR___name__), MP_ROM_QSTR(MP_QSTR_codecs) },

    { MP_ROM_QSTR(MP_QSTR_b32_encode), MP_ROM_PTR(&tz_b32_encode_obj) },
    { MP_ROM_QSTR(MP_QSTR_b32_decode), MP_ROM_PTR(&tz_b32_decode_obj) },

    { MP_ROM_QSTR(MP_QSTR_b58_encode), MP_ROM_PTR(&tz_b58_encode_obj) },
    { MP_ROM_QSTR(MP_QSTR_b58_decode), MP_ROM_PTR(&tz_b58_decode_obj) },

    { MP_ROM_QSTR(MP_QSTR_segwit_encode), MP_ROM_PTR(&tz_segwit_encode_obj) },
    { MP_ROM_QSTR(MP_QSTR_segwit_decode), MP_ROM_PTR(&tz_segwit_decode_obj) },
};
STATIC MP_DEFINE_CONST_DICT(mp_module_codecs_globals, mp_module_codecs_globals_table);

const mp_obj_module_t mp_module_codecs = {
    .base = { &mp_type_module },
    .globals = (mp_obj_dict_t *)&mp_module_codecs_globals,
};

// EOF
