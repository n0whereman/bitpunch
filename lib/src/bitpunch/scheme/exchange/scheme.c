#include "scheme.h"

#ifdef BPU_CONF_MECS_HYBRID
#include <bitpunch/debugio.h>
#include <bitpunch/math/gf2.h>
#include <bitpunch/bitpunch.h>
#include <bitpunch/crypto/hybrid/hybrid.h>

int BPU_KeyExchangeMecs(const BPU_T_Mecs_Ctx *ctx1, const BPU_T_Mecs_Ctx *ctx2) {
    BPU_T_Mecs_Ctx *ctx3 = NULL;
    BPU_T_UN_Mecs_Params params;

    /***************************************/
    // mce initialisation t = 50, m = 11
    fprintf(stderr, "Basic GOPPA Initialisation...\n");
    if (BPU_mecsInitParamsGoppa(&params, 11, 50, 0)) {
        return 1;
    }

    //A generates an ephemeral key
    if (BPU_mecsInitCtx(&ctx3, &params, BPU_EN_MECS_BASIC_GOPPA)) {
        return 1;
    }
    /***************************************/
    fprintf(stderr, "Key generation...\n");
    // key pair generation
    if (BPU_mecsGenKeyPair(ctx3)) {
        BPU_printError("Key generation error");

        return 1;
    }

   /* int err;
    BPU_T_GF2_Vector *pt_dem_a,*pt_dem_b, *ct_kem;
    BPU_gf2VecMalloc(&ct_kem,3072);
    BPU_gf2VecMalloc(&pt_dem_a,1152);
    BPU_gf2VecRand(pt_dem_a,20);
    BPU_gf2VecMalloc(&pt_dem_b,1152);

    BPU_printGf2Vec(pt_dem_a);
    //              Alice
    /***************************************/

    //BPU_hybridEncrypt(ct_kem,pt_dem_a, ctx1);

    //              Bob
    /***************************************/
//    BPU_hybridDecrypt(pt_dem_b,ct_kem, ctx1);

    /*if(BPU_gf2VecCmp(pt_dem_a,pt_dem_b) == 0){
        fprintf(stderr, "\nMessage was transferred\n");
    }

    //Releasing used memory
    BPU_gf2VecFree(&ct_kem);
    BPU_gf2VecFree(&pt_dem_b);
    BPU_gf2VecFree(&pt_dem_a);*/

	return 0;
}
#endif
