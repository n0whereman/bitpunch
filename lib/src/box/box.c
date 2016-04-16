#include "box.h"

#ifdef BPU_CONF_MECS_HYBRID
#include <bitpunch/debugio.h>
#include <bitpunch/math/gf2.h>
#include <bitpunch/bitpunch.h>
#include <bitpunch/crypto/hash/sha512.h>
#include <bitpunch/asn1/asn1.h>
//ToDO: prerobit zavislosti na utils
#include <bitpunch/crypto/aes/aes.h>
#include <bitpunch/crypto/kdf/pbkdf2.h>
#include <bitpunch/crypto/mac/mac.h>

int BPU_cryptobox_send(BPU_T_GF2_Vector *out, BPU_T_GF2_Vector *in, const BPU_T_Mecs_Ctx *ctx) {
        BPU_T_GF2_Vector *key_enc,*key_auth,*mac_salt, *enc_salt,*ct_dem, *iv_dem,*mac,*pt_kem,*pt_kem_pad,*tmp_out,*iv_salt;
        int err = 0;
        int pt_kem_size = 0;
        int pt_kem_pad_size = 0;

        //Alloc memory for mac
        BPU_gf2VecMalloc(&mac,BPU_MAC_LEN);
        //Alloc memory for IV
        BPU_gf2VecMalloc(&iv_dem,128);

        //TODO: CT_DEM should be divisible by 16, otherwise padding || 976
        BPU_gf2VecMalloc(&ct_dem,in->len);

        //Alloc memory for keys
        BPU_gf2VecMalloc(&key_enc,BPU_MAC_LEN);
        BPU_gf2VecMalloc(&key_auth,BPU_MAC_LEN);

        //Must be defined as protocol constant
        BPU_gf2VecMalloc(&enc_salt,BPU_MAC_LEN);
        BPU_gf2VecMalloc(&mac_salt,BPU_MAC_LEN);
        BPU_gf2VecMalloc(&iv_salt,BPU_MAC_LEN);
        BPU_gf2ArraytoVector(enc_salt,encsalt);
        BPU_gf2ArraytoVector(mac_salt,macsalt);
        BPU_gf2ArraytoVector(iv_salt,ivsalt);

        //Compute keys for enc and mac
        BPU_gf2VecKDF(key_enc,ctx->code_ctx->e, enc_salt, BPU_MAC_LEN);
        BPU_gf2VecKDF(key_auth,ctx->code_ctx->e, mac_salt,BPU_MAC_LEN);
        BPU_gf2VecKDF(iv_dem,ctx->code_ctx->e, iv_salt, BPU_MAC_LEN / 2);


        //DEM encryption
        err += BPU_gf2VecAesEnc(ct_dem,in,key_enc,iv_dem);

        //MAC computation
        BPU_gf2VecComputeHMAC(mac,ct_dem, key_auth);

        //Concatination of AES_ENC(M) and HMAC(m)
        pt_kem_size = ct_dem->len + mac->len;
        BPU_gf2VecMalloc(&pt_kem,pt_kem_size);
        BPU_gf2VecConcat(pt_kem,ct_dem,mac);

        //ADD padding if required, beaware 1498 len pre dane params MECS
        pt_kem_pad_size = ctx->pt_len - pt_kem_size;
        BPU_gf2VecMalloc(&pt_kem_pad, ctx->pt_len);
        BPU_padAdd(pt_kem_pad,pt_kem,pt_kem_pad_size);

        fprintf(stderr, "MECS encryption...\n");
        if (BPU_mecsBasicEncrypt(out, pt_kem_pad, ctx,0)) {
            BPU_printError("Encryption error");
            BPU_gf2VecFree(&ctx);
            BPU_gf2VecFree(&pt_kem_pad);
            BPU_gf2VecFree(&pt_kem);
            return 1;
        }

        BPU_gf2VecFree(&iv_dem);
        BPU_gf2VecFree(&ct_dem);
        BPU_gf2VecFree(&key_auth);
        BPU_gf2VecFree(&key_enc);
        BPU_gf2VecFree(&mac_salt);
        BPU_gf2VecFree(&enc_salt);

	return 0;
}


int BPU_cryptobox_recieve(BPU_T_GF2_Vector *out, BPU_T_GF2_Vector *in, const BPU_T_Mecs_Ctx *ctx) {
    int err = 0;
        BPU_T_GF2_Vector *pt_kem_dec_pad,*pt_kem_dec,*enc_salt,*mac_salt,*mac_a,*mac_b,*key_enc,*key_auth,*ct_dem, *iv_dem, *iv_salt;
        //Alloc memory for decrypted MECS, TODO: nerobim to natrvdo
        BPU_gf2VecMalloc(&pt_kem_dec_pad, ctx->pt_len);
        BPU_gf2VecMalloc(&pt_kem_dec, ctx->pt_len);
        BPU_gf2VecMalloc(&iv_dem,128);

        //Allocation of memory for macs SHA256
        BPU_gf2VecMalloc(&mac_a, BPU_MAC_LEN);
        BPU_gf2VecMalloc(&mac_b, BPU_MAC_LEN);

        fprintf(stderr, "MECS decryption...\n");
         if (BPU_mecsBasicDecrypt(pt_kem_dec_pad, in, ctx)) {
             BPU_printError("Decryption error");
             BPU_gf2VecFree(&ctx);
             BPU_gf2VecFree(&pt_kem_dec_pad);
             return 1;
         }

         //Remove padding
         BPU_padDel(pt_kem_dec,pt_kem_dec_pad);

        //Alloc memory for keys
        BPU_gf2VecMalloc(&key_enc,BPU_MAC_LEN);
        BPU_gf2VecMalloc(&key_auth,BPU_MAC_LEN);

        //Must be defined as protocol constant
        BPU_gf2VecMalloc(&enc_salt,BPU_MAC_LEN);
        BPU_gf2VecMalloc(&mac_salt,BPU_MAC_LEN);
        BPU_gf2VecMalloc(&iv_salt,BPU_MAC_LEN);
        BPU_gf2ArraytoVector(enc_salt,encsalt);
        BPU_gf2ArraytoVector(mac_salt,macsalt);
        BPU_gf2ArraytoVector(iv_salt,ivsalt);

        //Compute keys for enc and mac
        BPU_gf2VecKDF(key_enc,ctx->code_ctx->e, enc_salt, BPU_MAC_LEN);
        BPU_gf2VecKDF(key_auth,ctx->code_ctx->e, mac_salt, BPU_MAC_LEN);
        BPU_gf2VecKDF(iv_dem,ctx->code_ctx->e, iv_salt, BPU_MAC_LEN / 2);


         BPU_gf2VecMalloc(&ct_dem,pt_kem_dec->len - BPU_MAC_LEN);
         BPU_gf2VecCrop(ct_dem,pt_kem_dec,0,pt_kem_dec->len - BPU_MAC_LEN);
         BPU_gf2VecCrop(mac_a,pt_kem_dec,pt_kem_dec->len - BPU_MAC_LEN,BPU_MAC_LEN);

         BPU_gf2VecComputeHMAC(mac_b,ct_dem, key_auth);

         if(BPU_gf2VecCmp(mac_a,mac_b) == 0){
             fprintf(stderr, "\nMACs are equal\n");
         }
        //DEM decryption
        err += BPU_gf2VecAesDec(out,ct_dem,key_enc,iv_dem);
    return 0;
}
#endif
