#include "scheme.h"

#ifdef BPU_CONF_MECS_HYBRID
#include <bitpunch/debugio.h>
#include <bitpunch/math/gf2.h>
#include <bitpunch/bitpunch.h>
#include <bitpunch/crypto/hybrid/hybrid.h>

int BPU_HybridMecs(const BPU_T_Mecs_Ctx *ctx1, const BPU_T_Mecs_Ctx *ctx2) {
    int err;
    //MECS can process up to 64 bytes
    BPU_T_GF2_Vector *pt_dem_a,*pt_dem_b, *ct_kem;
    BPU_gf2VecMalloc(&ct_kem,3072);
    BPU_gf2VecMalloc(&pt_dem_a,976);
    BPU_gf2VecMalloc(&pt_dem_b,976);

    //              Alice
    /***************************************/
    BPU_hybridEncrypt(ct_kem,pt_dem_a, ctx1);
    //BPU_printGf2Vec(pt_dem_a);
    //              Bob
    /***************************************/
    BPU_hybridDecrypt(pt_dem_b,ct_kem, ctx1);
    //BPU_printGf2Vec(pt_dem_b);

    if(BPU_gf2VecCmp(pt_dem_a,pt_dem_b) == 0){
        fprintf(stderr, "\nMessage was transferred\n");
    }

    //Releasing used memory
    BPU_gf2VecFree(&ct_kem);
    BPU_gf2VecFree(&pt_dem_b);
    BPU_gf2VecFree(&pt_dem_a);

	return 0;
}
#endif
