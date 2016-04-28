#include "box.h"

#ifdef BPU_CONF_MECS_HYBRID
#include <bitpunch/debugio.h>
#include <bitpunch/math/gf2.h>
#include <math.h>
#include <bitpunch/bitpunch.h>
#include <bitpunch/crypto/hash/sha512.h>
#include <bitpunch/asn1/asn1.h>
//ToDO: prerobit zavislosti na utils
#include <bitpunch/crypto/padding/padding.h>

int BPU_cryptobox_send(BPU_T_GF2_Vector *out, BPU_T_GF2_Vector *in, const char *pk, int size) {
        BPU_T_GF2_Vector *key_enc,*mecs_out,*rest,*mecs_block,*tag, *enc_salt,*ct_dem, *iv_dem,*pt_kem,*iv_salt,*in_pad;
        int err = 0;
        int pad_len = 0;
        int pt_kem_size = 0;
        int mecs_block_size = 0;
        int aes_blocks_num = 0;
        int aes_blocks_bit = 0;

        //Set PK to context
        BPU_T_Mecs_Ctx *ctx = NULL;
        BPU_asn1DecodePubKey(&ctx,pk,size);

        //Allocate memory for mecs output
        BPU_gf2VecMalloc(&mecs_out,ctx->ct_len);

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
        BPU_gf2VecMalloc(&mecs_block,ctx->pt_len);
        BPU_gf2VecMalloc(&iv_salt,BPU_MAC_LEN);
        BPU_gf2ArraytoVector(enc_salt,encsalt);
        BPU_gf2ArraytoVector(iv_salt,ivsalt);

        //Compute keys for enc and mac
        BPU_gf2VecKDF(key_enc,ctx->code_ctx->e, enc_salt, BPU_MAC_LEN);
        BPU_gf2VecKDF(iv_dem,ctx->code_ctx->e, iv_salt, BPU_MAC_LEN / 2);

        mecs_block_size = ctx->pt_len - tag->len;
        //How many AES blocks? || 11 for given params
        float blocks = (float) mecs_block_size / (float) AES_SIZE;
        aes_blocks_num = (int) ceil(blocks);
        aes_blocks_bit = AES_SIZE * aes_blocks_num;

        //Padding to (11) AES_blocks
        if(in->len < aes_blocks_bit){
            //Allocate memory for in padded
            BPU_gf2VecMalloc(&in_pad, aes_blocks_bit);
            //Allocate memory for ct_dem
            BPU_gf2VecMalloc(&ct_dem,aes_blocks_bit);
            pad_len = aes_blocks_bit - in->len;
            BPU_padAdd(in_pad,in,pad_len);
        } else if (in->len > aes_blocks_bit && (in->len % 128 != 0)){
            float blocks = (float) in->len / (float) AES_SIZE;
            aes_blocks_num = (int) ceil(blocks);
            aes_blocks_bit = AES_SIZE * aes_blocks_num;
            BPU_printError("aes_blocks_bit %d: \n",aes_blocks_bit);
            //Allocate memory for in padded
            BPU_gf2VecMalloc(&in_pad, aes_blocks_bit);
            //Allocate memory for ct_dem
            BPU_gf2VecMalloc(&ct_dem,aes_blocks_bit);
            pad_len = aes_blocks_bit - in->len;
            BPU_padAdd(in_pad,in,pad_len);
        } else {
            float blocks = (float) in->len / (float) AES_SIZE;
            aes_blocks_num = (int) ceil(blocks);
            aes_blocks_bit = AES_SIZE * aes_blocks_num + AES_SIZE;
            BPU_printError("aes_blocks_bit %d: \n",aes_blocks_bit);
            //Allocate memory for in padded
            BPU_gf2VecMalloc(&in_pad, aes_blocks_bit);
            //Allocate memory for ct_dem
            BPU_gf2VecMalloc(&ct_dem,aes_blocks_bit);
            pad_len = aes_blocks_bit - in->len;
            BPU_padAdd(in_pad,in,pad_len);
        }

        //DEM encryption + auth
        err += BPU_gf2VecAesEncandTag(ct_dem,in_pad,tag,key_enc,iv_dem);

        //Concatination of AES_ENC(m) and TAG(m)
        pt_kem_size = ct_dem->len + tag->len;
        BPU_gf2VecMalloc(&pt_kem,pt_kem_size);
        BPU_gf2VecConcat(pt_kem,ct_dem,tag);

        //cropp the buffer to fit mecsblock
        BPU_gf2VecCrop(mecs_block, pt_kem, 0,ctx->pt_len);

        //cropp the rest
        BPU_gf2VecMalloc(&rest,pt_kem->len - ctx->pt_len);
        BPU_gf2VecCrop(rest, pt_kem, ctx->pt_len,pt_kem->len - ctx->pt_len);

        fprintf(stderr, "MECS encryption...\n");
        if (BPU_mecsBasicEncrypt(mecs_out, mecs_block, ctx,0)) {
            BPU_printError("Encryption error");
            BPU_mecsFreeCtx(&ctx);
            BPU_gf2VecFree(&mecs_out);
            BPU_gf2VecFree(&rest);
            BPU_gf2VecFree(&mecs_block);
            BPU_gf2VecFree(&iv_dem);
            BPU_gf2VecFree(&iv_salt);
            BPU_gf2VecFree(&in_pad);
            BPU_gf2VecFree(&pt_kem);
            BPU_gf2VecFree(&ct_dem);
            BPU_gf2VecFree(&key_enc);
            BPU_gf2VecFree(&enc_salt);
            BPU_gf2VecFree(&tag);
            return 1;
        }

        BPU_gf2VecConcat(out, mecs_out,rest);

        BPU_gf2VecFree(&mecs_block);
        BPU_gf2VecFree(&rest);
        BPU_gf2VecFree(&mecs_out);
        BPU_gf2VecFree(&iv_dem);
        BPU_gf2VecFree(&iv_salt);
        BPU_gf2VecFree(&in_pad);
        BPU_gf2VecFree(&pt_kem);
        BPU_gf2VecFree(&ct_dem);
        BPU_gf2VecFree(&key_enc);
        BPU_gf2VecFree(&enc_salt);
        BPU_gf2VecFree(&tag);
        BPU_mecsFreeCtx(&ctx);

	return 0;
}


int BPU_cryptobox_recieve(BPU_T_GF2_Vector *out, BPU_T_GF2_Vector *in, const BPU_T_Mecs_Ctx *ctx) {
        BPU_T_GF2_Vector *tag,*pt_dem,*ct_dem_tag,*mecs_dec,*enc_salt,*key_enc,*ct_dem, *iv_dem, *iv_salt,*rest,*mecs_block;

        BPU_gf2VecMalloc(&mecs_block, ctx->ct_len);
        BPU_gf2VecMalloc(&rest, in->len - ctx->ct_len);
        BPU_gf2VecMalloc(&mecs_dec, ctx->pt_len);

        if(in->len > ctx->ct_len){
            BPU_gf2VecCrop(mecs_block, in, 0,ctx->ct_len);
            BPU_gf2VecCrop(rest, in, ctx->ct_len, in->len - ctx->ct_len);
        }

        //Allocation of memory for TAG
        BPU_gf2VecMalloc(&tag, 128);

        //Allocation of memory for IV
        BPU_gf2VecMalloc(&iv_dem,128);

        fprintf(stderr, "MECS decryption...\n");
         if (BPU_mecsBasicDecrypt(mecs_dec, mecs_block, ctx)) {
             //BPU_printError("Decryption error"); || Generate a random error vector in order to prevent reaction attacks
             BPU_gf2VecRand(ctx->code_ctx->e, 20);
         }

        BPU_gf2VecMalloc(&ct_dem_tag, mecs_dec->len + rest->len);
        BPU_gf2VecConcat(ct_dem_tag,mecs_dec,rest);

        //Aloocate memory for ct_dem
        BPU_gf2VecMalloc(&ct_dem,ct_dem_tag->len - tag->len);

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

         BPU_gf2VecCrop(ct_dem,ct_dem_tag,0,ct_dem_tag->len - tag->len);
         BPU_gf2VecMalloc(&pt_dem, ct_dem->len);
         BPU_gf2VecCrop(tag,ct_dem_tag,ct_dem_tag->len - tag->len,tag->len);

        //DEM decryption

        if(BPU_gf2VecAesDecandTag(pt_dem,ct_dem,tag,key_enc,iv_dem)){
            BPU_printError("Could not be decrypted\n");
            BPU_gf2VecFree(&tag);
            BPU_gf2VecFree(&pt_dem);
            BPU_gf2VecFree(&ct_dem_tag);
            BPU_gf2VecFree(&mecs_dec);
            BPU_gf2VecFree(&enc_salt);
            BPU_gf2VecFree(&key_enc);
            BPU_gf2VecFree(&ct_dem);
            BPU_gf2VecFree(&iv_dem);
            BPU_gf2VecFree(&iv_salt);
            BPU_gf2VecFree(&mecs_block);
            BPU_gf2VecFree(&rest);
            return 1;
        }

        BPU_padDel(out,pt_dem);

        //BPU_printError("OUT:");
       // BPU_printGf2Vec(out);

        //Release memory
        BPU_gf2VecFree(&tag);
        BPU_gf2VecFree(&pt_dem);
        BPU_gf2VecFree(&ct_dem_tag);
        BPU_gf2VecFree(&mecs_dec);
        BPU_gf2VecFree(&enc_salt);
        BPU_gf2VecFree(&key_enc);
        BPU_gf2VecFree(&ct_dem);
        BPU_gf2VecFree(&iv_dem);
        BPU_gf2VecFree(&iv_salt);
       // ToDo: preco nebyva initialized? BPU_gf2VecFree(&mecs_block);
        BPU_gf2VecFree(&rest);

        return 0;
}
#endif
