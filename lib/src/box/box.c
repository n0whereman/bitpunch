#include "box.h"

#ifdef BPU_CONF_MECS_HYBRID
#include <bitpunch/debugio.h>
#include <bitpunch/math/gf2.h>
#include <math.h>
#include <bitpunch/bitpunch.h>
#include <bitpunch/crypto/hash/sha512.h>
#include <bitpunch/asn1/asn1.h>
//ToDO: prerobit zavislosti na utils
#include <bitpunch/crypto/aes/aes.h>
#include <bitpunch/crypto/kdf/pbkdf2.h>
#include <bitpunch/crypto/mac/mac.h>
#include <bitpunch/crypto/padding/padding.h>

int BPU_cryptobox_send(BPU_T_GF2_Vector *out, BPU_T_GF2_Vector *in, const BPU_T_Mecs_Ctx *ctx) {
        BPU_T_GF2_Vector *key_enc,*tag,*mac_salt, *enc_salt,*ct_dem, *iv_dem,*mac,*pt_kem,*pt_kem_pad,*iv_salt, *ct_dem_pad,*in_pad;
        int err = 0;
        int pad_len = 0;
        int pt_kem_size = 0;
        int mecs_block_size = 0;
        int aes_blocks_num = 0;
        int aes_blocks = 0;
        int pt_kem_pad_size = 0;

        //Alloc memory for IV, at least 16 bytes
        BPU_gf2VecMalloc(&iv_dem,128);

        //Alloc memory for AUTH_TAG, at least 16 bytes
        BPU_gf2VecMalloc(&tag,128);

        //TODO: CT_DEM should be divisible by 128, otherwise padding
        if(in->len < 128){
            BPU_printError("Len must be at least 16 bytes\n");
            return -1;
        }


        //Alloc memory for keys
        BPU_gf2VecMalloc(&key_enc,BPU_MAC_LEN);

        //Must be defined as protocol constant
        BPU_gf2VecMalloc(&enc_salt,BPU_MAC_LEN);
        BPU_gf2VecMalloc(&iv_salt,BPU_MAC_LEN);
        BPU_gf2ArraytoVector(enc_salt,encsalt);
        BPU_gf2ArraytoVector(iv_salt,ivsalt);

        //Compute keys for enc and mac
        BPU_gf2VecKDF(key_enc,ctx->code_ctx->e, enc_salt, BPU_MAC_LEN);
        BPU_gf2VecKDF(iv_dem,ctx->code_ctx->e, iv_salt, BPU_MAC_LEN / 2);

        mecs_block_size = ctx->pt_len - tag->len;

        //How many AES blocks? || 10 for given params
        aes_blocks_num = (int) floor(mecs_block_size / 128);
        aes_blocks = 128 * aes_blocks_num;
        BPU_printError("aes_blocks je %d\n", aes_blocks);
        BPU_gf2VecMalloc(&in_pad, aes_blocks);

        //Allocate memory for ct_dem
        BPU_gf2VecMalloc(&ct_dem,aes_blocks);

        //Padding to (10) AES_blocks
        if(in->len < aes_blocks){
            pad_len = aes_blocks - in->len;
            BPU_printError("Idem paduvat %d\n", pad_len);
            BPU_padAdd(in_pad,in,pad_len);
        }
        BPU_printError("In padded: \n");
        BPU_printGf2Vec(in_pad);

        //DEM encryption + auth
        err += BPU_gf2VecAesEncandTag(ct_dem,in_pad,tag,key_enc,iv_dem);

        BPU_printError("TAG: \n");
        BPU_printGf2Vec(tag);

        BPU_printError("Sifruvane aesem: \n");
        BPU_printGf2Vec(ct_dem);

        //Concatination of AES_ENC(m) and TAG(m)
        pt_kem_size = ct_dem->len + tag->len;
        BPU_gf2VecMalloc(&pt_kem,pt_kem_size);
        BPU_gf2VecConcat(pt_kem,ct_dem,tag);

        //ADD padding if required, beaware 1498 len pre dane params MECS
        pt_kem_pad_size = ctx->pt_len - pt_kem->len;
        BPU_gf2VecMalloc(&pt_kem_pad, ctx->pt_len);
        BPU_padAdd(pt_kem_pad,pt_kem,pt_kem_pad_size);

        BPU_printError("PT_kem_pad: \n");
        BPU_printGf2Vec(pt_kem_pad);

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
        BPU_gf2VecFree(&key_enc);
        BPU_gf2VecFree(&enc_salt);

	return 0;
}


int BPU_cryptobox_recieve(BPU_T_GF2_Vector *out, BPU_T_GF2_Vector *in, const BPU_T_Mecs_Ctx *ctx) {
       int err = 0;
       int aes_blocks_num = 0;
       int aes_blocks = 0;
       int mecs_block_size = 0;
        BPU_T_GF2_Vector *tag,*pt_kem_dec_pad,*pt_kem_dec,*enc_salt,*mac_a,*mac_b,*key_enc,*key_auth,*ct_dem, *iv_dem, *iv_salt;

        BPU_gf2VecMalloc(&pt_kem_dec_pad, ctx->pt_len);
        BPU_gf2VecMalloc(&pt_kem_dec, ctx->pt_len);

        //Allocation of memory for TAG
        BPU_gf2VecMalloc(&tag, 128);

        //Allocation of memory for IV
        BPU_gf2VecMalloc(&iv_dem,128);

        fprintf(stderr, "MECS decryption...\n");
         if (BPU_mecsBasicDecrypt(pt_kem_dec_pad, in, ctx)) {
             BPU_printError("Decryption error");
             BPU_gf2VecFree(&ctx);
             BPU_gf2VecFree(&pt_kem_dec_pad);
             return 1;
         }
         BPU_printError("MECS DECRYPTED: \n");
         BPU_printGf2Vec(pt_kem_dec_pad);

        //Remove padding
        BPU_padDel(pt_kem_dec,pt_kem_dec_pad);

        BPU_printError("Removed mecs padding: \n");
        BPU_printGf2Vec(pt_kem_dec);

        mecs_block_size = ctx->pt_len - tag->len;

        //How many AES blocks? || 10 for given params
        BPU_gf2VecMalloc(&ct_dem, pt_kem_dec->len - 128);

        //Alloc memory for keys
        BPU_gf2VecMalloc(&key_enc,BPU_MAC_LEN);

        //Must be defined as protocol constant
        BPU_gf2VecMalloc(&enc_salt,BPU_MAC_LEN);
        BPU_gf2VecMalloc(&iv_salt,BPU_MAC_LEN);
        BPU_gf2ArraytoVector(enc_salt,encsalt);
        BPU_gf2ArraytoVector(iv_salt,ivsalt);

        //Compute keys for enc and mac
        BPU_gf2VecKDF(key_enc,ctx->code_ctx->e, enc_salt, BPU_MAC_LEN);
        BPU_gf2VecKDF(iv_dem,ctx->code_ctx->e, iv_salt, BPU_MAC_LEN / 2);

         BPU_gf2VecCrop(ct_dem,pt_kem_dec,0,pt_kem_dec->len - 128);
         BPU_gf2VecCrop(tag,pt_kem_dec,pt_kem_dec->len - 128,128);

         BPU_printError("CT_DEM: \n");
         BPU_printGf2Vec(ct_dem);

         BPU_printError("TAG: \n");
         BPU_printGf2Vec(tag);

        //DEM decryption
        err += BPU_gf2VecAesDecandTag(out,ct_dem,tag,key_enc,iv_dem);

        BPU_printError("PT: \n");
        BPU_printGf2Vec(out);

        return 0;
}
#endif
