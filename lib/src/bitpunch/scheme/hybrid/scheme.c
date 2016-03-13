#include "scheme.h"

#ifdef BPU_CONF_MECS_HYBRID
#include <bitpunch/debugio.h>
#include <bitpunch/math/gf2.h>
#include <bitpunch/crypto/aes/aes.h>
#include <bitpunch/crypto/kdf/pbkdf2.h>
#include <bitpunch/bitpunch.h>

int BPU_HybridMecs(const BPU_T_Mecs_Ctx *ctx1, const BPU_T_Mecs_Ctx *ctx2) {
    int err;
    BPU_T_GF2_Vector *extended_pwd;
    BPU_gf2VecMalloc(&extended_pwd,384);
    BPU_gf2VecKDF(extended_pwd,ctx2->code_ctx->e);


	return 0;
}
#endif
