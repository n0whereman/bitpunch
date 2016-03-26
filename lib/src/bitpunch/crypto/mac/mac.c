/*
This file is part of BitPunch
Copyright (C) 2015 Frantisek Uhrecky <frantisek.uhrecky[what here]gmail.com>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/
#include "mac.h"

#ifdef BPU_CONF_MAC
#include "mbedtls/md.h"

#include <bitpunch/debugio.h>
#include <bitpunch/math/gf2.h>

int BPU_gf2VecComputeHMAC(BPU_T_GF2_Vector *out, const BPU_T_GF2_Vector *in, const BPU_T_GF2_Vector *key) {
	int res = 0;

  mbedtls_md_context_t ctx= {};
  const mbedtls_md_info_t * sha512_md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA512);
  mbedtls_md_init_ctx(&ctx, sha512_md);
  char output[64] = {};
  //char encoded[512] = {};
  
  res = mbedtls_md_hmac_starts(&ctx, (const unsigned char*) key->elements, key->len / 8);
  res = mbedtls_md_hmac_update(&ctx, (const unsigned char*)in->elements, in->len / 8);
  res = mbedtls_md_hmac_finish(&ctx, (unsigned char*)output);

  memcpy(out->elements, output, out->len / 8);

  mbedtls_md_free(&ctx);

	return 0;
}
#endif
