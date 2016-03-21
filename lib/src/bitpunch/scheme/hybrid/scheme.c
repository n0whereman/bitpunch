#include "scheme.h"

#ifdef BPU_CONF_MECS_HYBRID
#include <bitpunch/debugio.h>
#include <bitpunch/math/gf2.h>
#include <bitpunch/crypto/aes/aes.h>
#include <bitpunch/crypto/kdf/pbkdf2.h>
#include <bitpunch/crypto/mac/mac.h>
#include <bitpunch/crypto/padding/padding.h>
#include <bitpunch/bitpunch.h>

int BPU_HybridMecs(const BPU_T_Mecs_Ctx *ctx1, const BPU_T_Mecs_Ctx *ctx2) {
    int err;
    //MECS can process up to 64 bytes
    BPU_T_GF2_Vector *iv_orig,*ke, *salt, *pt_dem_a,*pt_dem_b, *ct_dem_a, *ct_dem_b,*iv_dem, *mac_a, *ka, *pt_kem, *ct_kem,*pt_kem_dec, *pt_kem_pad,*mac_b, *pt_kem_dec_pad;
    BPU_gf2VecMalloc(&pt_kem,1488);
    BPU_gf2VecMalloc(&pt_kem_pad,1498);
    BPU_gf2VecMalloc(&pt_kem_dec_pad,1498);
    BPU_gf2VecMalloc(&pt_kem_dec,1488);
    BPU_gf2VecMalloc(&ct_kem,3072);
    BPU_gf2VecMalloc(&pt_dem_a,976);
    BPU_gf2VecMalloc(&pt_dem_b,976);
    BPU_gf2VecRand(pt_dem_a, 5);
    BPU_gf2VecMalloc(&iv_dem,256);
    BPU_gf2VecMalloc(&iv_orig,256);
    BPU_gf2VecRand(iv_dem,3);
    BPU_gf2VecMalloc(&ct_dem_a,976);
    BPU_gf2VecMalloc(&ct_dem_b,976);
    BPU_gf2VecMalloc(&salt,256);
    BPU_gf2VecMalloc(&ke,256);
    BPU_gf2VecMalloc(&ka,256);
    BPU_gf2VecMalloc(&mac_a,512);
    BPU_gf2VecMalloc(&mac_b,512);

    BPU_gf2VecCopy(iv_orig,iv_dem);

    //party A
    BPU_gf2VecKDF(ke,ctx2->code_ctx->e, salt);
    //TODO: should I really change the salt? be aware of padding | ako prenasat IV na AES?
    BPU_gf2VecKDF(ka,ctx2->code_ctx->e, salt);
    err += BPU_gf2VecAesEnc(ct_dem_a,pt_dem_a,ke,iv_dem);
    BPU_gf2VecComputeHMAC(mac_a,pt_dem_a, ka);

    BPU_gf2VecConcat(pt_kem,ct_dem_a,mac_a);
    BPU_padAdd(pt_kem_pad,pt_kem,10);
    fprintf(stderr, "PT to MECS: \n");
    BPU_printGf2Vec(pt_kem_pad);

    fprintf(stderr, "Encryption...\n");
    // BPU_encrypt pt
    if (BPU_mecsEncrypt(ct_kem, pt_kem_pad, ctx2)) {
        BPU_printError("Encryption error");

        BPU_gf2VecFree(&ctx2);
        BPU_gf2VecFree(&pt_kem);
        BPU_gf2VecFree(&ct_kem);
        return 1;
    }
    //              Bob
    /***************************************/

    fprintf(stderr, "Decryption...\n");
    // decrypt cipher text
    if (BPU_mecsDecrypt(pt_kem_dec_pad, ct_kem, ctx2)) {
        BPU_printError("Decryption error");

        BPU_gf2VecFree(&ctx2);
        BPU_gf2VecFree(&ct_kem);
        BPU_gf2VecFree(&pt_kem_dec);
        return 1;
    }
    fprintf(stderr, "DECRYPTED...\n");
    //BPU_printGf2Vec(pt_kem_dec);
    BPU_padDel(pt_kem_dec_pad,pt_kem_dec);
    //TODO: deallocuj bordel*/
    BPU_gf2VecKDF(ke,ctx2->code_ctx->e, salt);
    //TODO: should I really change the salt? be aware of padding | ako prenasat IV na AES?
    BPU_gf2VecKDF(ka,ctx2->code_ctx->e, salt);
    BPU_gf2VecCrop(mac_b,pt_kem_dec,976,512);

    if(BPU_gf2VecCmp(mac_a,mac_b)){
        fprintf(stderr, "\nMACs matches\n");
    }
    BPU_gf2VecCrop(ct_dem_b,pt_kem_dec,0,976);
    BPU_gf2VecCopy(iv_dem,iv_orig);
    err += BPU_gf2VecAesDec(pt_dem_b,ct_dem_b,ke,iv_dem);

    if(BPU_gf2VecCmp(pt_dem_a,pt_dem_b)){
        fprintf(stderr, "\nMessage was transferred\n");
    }

	return 0;
}
#endif
