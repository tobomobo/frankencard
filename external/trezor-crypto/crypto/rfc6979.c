/**
 * Copyright (c) 2013-2014 Tomas Dzetkulic
 * Copyright (c) 2013-2014 Pavol Rusnak
 * Copyright (c)      2015 Jochen Hoenicke
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES
 * OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */
#include <assert.h>
#include <string.h>  // COLDCARD-ADDED: memcpy, for init_rfc6979_ex

#include "hmac_drbg.h"
#include "memzero.h"
#include "rfc6979.h"

// COLDCARD-ADDED: `extra`, when non-NULL, is 32 bytes of additional nonce
// entropy appended to the DRBG seed material, giving seed = priv || hash ||
// extra. This matches libsecp256k1's nonce_function_rfc6979 keydata layout
// (key32 || msg32 || data32) so the derived k -- and therefore the signature --
// is byte-identical to libsecp256k1's for the same inputs. Needed because
// Coldcard grinds this value to find low-R signatures.
void init_rfc6979_ex(const uint8_t *priv_key, const uint8_t *hash,
                     const uint8_t *extra, const ecdsa_curve *curve,
                     rfc6979_state *state) {
  uint8_t nonce[64] = {0};
  size_t nonce_len = extra ? 64 : 32;

  if (curve) {
    bignum256 hash_bn = {0};
    bn_read_be(hash, &hash_bn);

    // Make sure hash is partly reduced modulo order
    assert(bn_bitcount(&curve->order) >= 256);
    bn_mod(&hash_bn, &curve->order);

    bn_write_be(&hash_bn, nonce);
    memzero(&hash_bn, sizeof(hash_bn));
  } else {
    memcpy(nonce, hash, 32);
  }

  if (extra) {
    memcpy(nonce + 32, extra, 32);
  }

  hmac_drbg_init(state, priv_key, 32, nonce, nonce_len);
  memzero(nonce, sizeof(nonce));
}

void init_rfc6979(const uint8_t *priv_key, const uint8_t *hash,
                  const ecdsa_curve *curve, rfc6979_state *state) {
  init_rfc6979_ex(priv_key, hash, NULL, curve, state);
}

// generate next number from deterministic random number generator
void generate_rfc6979(uint8_t rnd[32], rfc6979_state *state) {
  hmac_drbg_generate(state, rnd, 32);
}

// generate K in a deterministic way, according to RFC6979
// http://tools.ietf.org/html/rfc6979
void generate_k_rfc6979(bignum256 *k, rfc6979_state *state) {
  uint8_t buf[32] = {0};
  generate_rfc6979(buf, state);
  bn_read_be(buf, k);
  memzero(buf, sizeof(buf));
}
