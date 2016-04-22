/*
 This file is part of BitPunch
 Copyright (C) 2014-2015 Frantisek Uhrecky <frantisek.uhrecky[what here]gmail.com>

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
#include <bitpunch/bitpunch.h>
#include <box/box.h>

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <sys/time.h>


int testKDF(){
    BPU_T_GF2_Vector *extended_pwd, *pwd, *salt;
    BPU_gf2VecMalloc(&pwd,64);
    BPU_gf2VecMalloc(&salt,64);
    //pomocny
    BPU_gf2VecMalloc(&extended_pwd,512);
    BPU_gf2VecKDF(extended_pwd,pwd, salt, 512);
    return 0;
}

int testMAC(){
    BPU_T_GF2_Vector *in, *key, *out;
    BPU_gf2VecMalloc(&key,64);
    BPU_gf2VecRand(key,3);
    BPU_gf2VecMalloc(&in,64);
    BPU_gf2VecRand(in,3);
    BPU_gf2VecMalloc(&out,512);
    //pomocny
    BPU_gf2VecComputeHMAC(out,in, key);
    return 0;
}

int testAesEncDec(){
    int rc = 0;
    fprintf(stderr, "Aes - ENC/DEC testing...\n");
    BPU_T_GF2_Vector *pt, *ct,*key,*iv,*tmp, *ivOrig;
    //Testing plaintext vector - lenght 384 bit ()
    BPU_gf2VecMalloc(&pt,256);
    BPU_gf2VecRand(pt,3);
    //pomocny
    BPU_gf2VecMalloc(&tmp,256);
    BPU_gf2VecCopy(tmp,pt);
    BPU_gf2VecMalloc(&ct,256);
    //Testing iv vector, must be 16 bytes
    BPU_gf2VecMalloc(&iv,16*8);
    BPU_gf2VecRand(iv,3);
    BPU_gf2VecMalloc(&ivOrig,16*8);
    BPU_gf2VecCopy(ivOrig,iv);
    //Testing key vector, must be 32 bytes
    BPU_gf2VecMalloc(&key,32*8);
    BPU_gf2VecRand(key,3);
    
    rc += BPU_gf2VecAesEnc(ct,pt,key,iv);
    BPU_gf2VecCopy(iv,ivOrig);
    rc += BPU_gf2VecAesDec(pt,ct,key,iv);

    if (BPU_gf2VecCmp(pt,tmp) == 0)
        fprintf(stderr, "CT is equal to PT.\n");
    return rc;
}

int testCryptoBox(){
    int rc = 0;
    BPU_T_UN_Mecs_Params params;
    BPU_T_GF2_Vector *pt_dem_a,*pt_dem_b, *ct_kem;
       BPU_gf2VecMalloc(&ct_kem,3072);
       BPU_gf2VecMalloc(&pt_dem_a,1921);
       BPU_gf2VecRand(pt_dem_a,20);

    /***************************************/
    // mce initialisation t = 50, m = 11
    fprintf(stderr, "Basic GOPPA Initialisation...\n");
    if (BPU_mecsInitParamsGoppa(&params, 11, 50, 0)) {
        return 1;
    }
    BPU_T_Mecs_Ctx *ctx = NULL;
    if (BPU_mecsInitCtx(&ctx, &params, BPU_EN_MECS_BASIC_GOPPA)) {
        return 1;
    }
    /***************************************/
    fprintf(stderr, "Key generation...\n");
    // key pair generation
    if (BPU_mecsGenKeyPair(ctx)) {
        BPU_printError("Key generation error");
        return 1;
    }

    BPU_printError("Calling cryptobox...\n");
    if(BPU_cryptobox_send(ct_kem,pt_dem_a, ctx)){
        BPU_printError("Hybrid scheme error");
        BPU_mecsFreeCtx(&ctx);
        BPU_mecsFreeParamsGoppa(&params);
    return 1;
    }

   if(BPU_cryptobox_recieve(pt_dem_a,ct_kem, ctx)){
        BPU_printError("Hybrid scheme error");
        BPU_mecsFreeCtx(&ctx);
        BPU_mecsFreeParamsGoppa(&params);
    return 1;
    }

    //Releasing used memory
    BPU_gf2VecFree(&ct_kem);
    BPU_gf2VecFree(&pt_dem_a);

    BPU_mecsFreeCtx(&ctx);
    BPU_mecsFreeParamsGoppa(&params);

    return rc;
}


int testKeyExchange(){
    int rc = 0;
    // MUST BE NULL
    BPU_T_Mecs_Ctx *ctx_A = NULL;
    BPU_T_Mecs_Ctx *ctx_B = NULL;
    BPU_T_Mecs_Ctx *ctx_E = NULL;
    BPU_T_UN_Mecs_Params params;
    BPU_T_GF2_Vector *r1,*pub_vec, *m1, *ct_kem, *m1_rec;
    char *buffer = NULL;
    int size;

    BPU_gf2VecMalloc(&r1,128);
    BPU_gf2VecRand(r1,20);


    /***************************************/
    // mce initialisation t = 50, m = 11
    fprintf(stderr, "Basic GOPPA Initialisation...\n");
    if (BPU_mecsInitParamsGoppa(&params, 11, 50, 0)) {
        return 1;
    }

    if (BPU_mecsInitCtx(&ctx_A, &params, BPU_EN_MECS_BASIC_GOPPA)) {
        return 1;
    }
    /***************************************/
    fprintf(stderr, "Key generation...\n");
    // key pair generation
    if (BPU_mecsGenKeyPair(ctx_A)) {
        BPU_printError("Key generation error");
        return 1;
    }

    if (BPU_mecsInitCtx(&ctx_B, &params, BPU_EN_MECS_BASIC_GOPPA)) {
        return 1;
    }
    /***************************************/
    fprintf(stderr, "Key generation...\n");
    // key pair generation
    if (BPU_mecsGenKeyPair(ctx_B)) {
        BPU_printError("Key generation error");
        return 1;
    }

    if (BPU_mecsInitCtx(&ctx_E, &params, BPU_EN_MECS_BASIC_GOPPA)) {
        return 1;
    }
    /***************************************/
    fprintf(stderr, "Key generation...\n");
    // key pair generation
    if (BPU_mecsGenKeyPair(ctx_E)) {
        BPU_printError("Key generation error");
        return 1;
    }

    BPU_gf2VecMalloc(&ct_kem,ctx_A->ct_len);

    //Encode ephemeral pk into buffer
    if (BPU_asn1EncodePubKey(&buffer, &size, ctx_E)) {
            return -1;
    }
    BPU_printError("Encoding pub key to buffer");
    BPU_gf2VecMalloc(&pub_vec,size);
    BPU_gf2ArraytoVector(pub_vec,buffer);

    //Allocate memory for m1
    BPU_gf2VecMalloc(&m1,pub_vec->len + r1->len);

    BPU_gf2VecConcat(m1,r1, pub_vec);

    //A sends m1 to B
    if(BPU_cryptobox_send(ct_kem,m1, ctx_B)){
        BPU_printError("Hybrid scheme error");
        BPU_mecsFreeCtx(&ctx_B);
        BPU_mecsFreeParamsGoppa(&params);
    return 1;
    }
    BPU_printError("M1 has been sent\n");

    BPU_gf2VecMalloc(&m1_rec,m1->len);
    //B recieves m1
    if(BPU_cryptobox_recieve(m1_rec,ct_kem, ctx_B)){
         BPU_printError("Hybrid scheme error");
         BPU_mecsFreeCtx(&ctx_B);
         BPU_mecsFreeParamsGoppa(&params);
     return 1;
     }
    BPU_printError("M1 has been recieved\n");
    BPU_printError("m1_rec:");
    BPU_printGf2Vec(m1_rec);


    BPU_mecsFreeCtx(&ctx_A);
    BPU_mecsFreeCtx(&ctx_B);
    BPU_mecsFreeParamsGoppa(&params);

    return rc;
}


int testCmpMecsCtx(const BPU_T_Mecs_Ctx *ctx1, const BPU_T_Mecs_Ctx *ctx2) {
    int i, j, rc = 0;
    if (ctx1->type != ctx2->type) {
        BPU_printError("type");
    }
    if (ctx1->ct_len != ctx2->ct_len) {
        BPU_printError("ct_len");
    }
    if (ctx1->pt_len != ctx2->pt_len) {
        BPU_printError("pt_len");
    }
    if (ctx1->_decrypt != ctx2->_decrypt) {
        BPU_printError("_decrypt");
    }
    if (ctx1->_encrypt != ctx2->_encrypt) {
        BPU_printError("_encrypt");
    }
    if (ctx1->code_ctx->code_len != ctx2->code_ctx->code_len) {
        BPU_printError("code_len");
    }
    if (ctx1->code_ctx->msg_len != ctx2->code_ctx->msg_len) {
        BPU_printError("msg_len");
    }
    if (ctx1->code_ctx->t != ctx2->code_ctx->t) {
        BPU_printError("t");
    }
    if (ctx1->code_ctx->type != ctx2->code_ctx->type) {
        BPU_printError("code type");
    }
    if (ctx1->code_ctx->_decode != ctx2->code_ctx->_decode) {
        BPU_printError("_decode");
    }
    if (ctx1->code_ctx->_encode != ctx2->code_ctx->_encode) {
        BPU_printError("_encode");
    }
    if (ctx1->code_ctx->e->len != ctx2->code_ctx->e->len) {
        BPU_printError("e.len");
    }
    if (BPU_gf2xPolyCmp(ctx1->code_ctx->code_spec->goppa->g, ctx2->code_ctx->code_spec->goppa->g)) {
        BPU_printError("g poly");
    }
    if (ctx1->code_ctx->code_spec->goppa->support_len != ctx2->code_ctx->code_spec->goppa->support_len) {
        BPU_printError("support len");
    }
    if (ctx1->code_ctx->code_spec->goppa->permutation->size != ctx2->code_ctx->code_spec->goppa->permutation->size) {
        BPU_printError("perm size");
    }
    if (ctx1->code_ctx->code_spec->goppa->g_mat->elements_in_row != ctx2->code_ctx->code_spec->goppa->g_mat->elements_in_row) {
        BPU_printError("g_mat elements_in_row");
    }
    if (ctx1->code_ctx->code_spec->goppa->g_mat->element_bit_size != ctx2->code_ctx->code_spec->goppa->g_mat->element_bit_size) {
        BPU_printError("g_mat element_bit_size");
    }
    if (ctx1->code_ctx->code_spec->goppa->g_mat->k != ctx2->code_ctx->code_spec->goppa->g_mat->k) {
        BPU_printError("g_mat k");
    }
    if (ctx1->code_ctx->code_spec->goppa->g_mat->n != ctx2->code_ctx->code_spec->goppa->g_mat->n) {
        BPU_printError("g_mat n");
    }
    for (i = 0; i < ctx1->code_ctx->code_spec->goppa->permutation->size; i++) {
        if (ctx1->code_ctx->code_spec->goppa->permutation->elements[i] != ctx2->code_ctx->code_spec->goppa->permutation->elements[i]) {
            BPU_printError("perm diff");
            break;
        }
    }
    if (ctx1->code_ctx->code_spec->goppa->h_mat->k != ctx2->code_ctx->code_spec->goppa->h_mat->k) {
        BPU_printError("h_mat k");
    }
    if (ctx1->code_ctx->code_spec->goppa->h_mat->n != ctx2->code_ctx->code_spec->goppa->h_mat->n) {
        BPU_printError("h_mat n");
    }
    for (i = 0; i < ctx1->code_ctx->code_spec->goppa->g_mat->elements_in_row; i++) {
        for (j = 0; j < ctx1->code_ctx->code_spec->goppa->g_mat->k; j++) {
            if (ctx1->code_ctx->code_spec->goppa->g_mat->elements[j][i] != ctx2->code_ctx->code_spec->goppa->g_mat->elements[j][i]) {
                BPU_printError("g_mat diff");
                j = -1;
                break;
            }
        }
        if (j == -1) {
            break;
        }
    }
    for (i = 0; i < ctx1->code_ctx->code_spec->goppa->h_mat->n; i++) {
        for (j = 0; j < ctx1->code_ctx->code_spec->goppa->h_mat->k; j++) {
            if (ctx1->code_ctx->code_spec->goppa->h_mat->elements[j][i] != ctx2->code_ctx->code_spec->goppa->h_mat->elements[j][i]) {
                BPU_printError("h_mat diff");
                j = -1;
                break;
            }
        }
        if (j == -1) {
            break;
        }
    }
    return rc;
}

int testKeyGenEncDec(BPU_T_Mecs_Ctx *ctx) {
//    BPU_T_Mecs_Ctx *ctx = NULL;
    BPU_T_GF2_Vector *ct, *pt_in, *pt_out;
	int rc = 0;

	/***************************************/
	fprintf(stderr, "Key generation...\n");
	// key pair generation
	if (BPU_mecsGenKeyPair(ctx)) {
//    if (BPU_asn1LoadKeyPair(&ctx, "prikey.der", "pubkey.der")) {
		BPU_printError("Key generation error");

		return 1;
	}
	/***************************************/
	// prepare plain text, allocate memory and init random plaintext
	if (BPU_gf2VecMalloc(&pt_in, ctx->pt_len)) {
		BPU_printError("PT initialisation error");

		return 1;
	}
    BPU_gf2VecRand(pt_in, 0);

	// alocate cipher text vector
	if (BPU_gf2VecMalloc(&ct, ctx->ct_len)) {
		BPU_printError("CT vector allocation error");

        BPU_gf2VecFree(&pt_in);
		return 1;
	}
	// prepare plain text, allocate memory and init random plaintext
	if (BPU_gf2VecMalloc(&pt_out, ctx->pt_len)) {
		BPU_printError("PT out initialisation error");

		return 1;
	}
    BPU_gf2VecRand(pt_out, 0);
	/***************************************/
	fprintf(stderr, "Encryption...\n");
	// BPU_encrypt plain text
    if (BPU_mecsEncrypt(ct, pt_in, ctx)) {
		BPU_printError("Encryption error");

        BPU_gf2VecFree(&ct);
        BPU_gf2VecFree(&pt_in);
        BPU_gf2VecFree(&pt_out);
		return 1;
	}
	// exit(0);
	/***************************************/
	fprintf(stderr, "Decryption...\n");
	// decrypt cipher text
    if (BPU_mecsDecrypt(pt_out, ct, ctx)) {
		BPU_printError("Decryption error");

        BPU_gf2VecFree(&ct);
        BPU_gf2VecFree(&pt_in);
        BPU_gf2VecFree(&pt_out);
        return 1;
    }
	/***************************************/

	// check for correct decryption
    if (BPU_gf2VecCmp(pt_in, pt_out)) {
		BPU_printError("\nOutput plain text differs from input");

		rc = 2;
	}
	else {
		fprintf(stderr, "\nSUCCESS: Input plain text is equal to output plain text.\n");
	}
	// clean up
	/***************************************/
	fprintf(stderr, "\nCleaning up...\n");
    BPU_gf2VecFree(&pt_in);
    BPU_gf2VecFree(&pt_out);
    BPU_gf2VecFree(&ct);
	return rc;
}

#ifdef BPU_CONF_ASN1
int testKeyGenAsn1() {
    int rc = 0;
    // MUST BE NULL
    BPU_T_Mecs_Ctx *ctx = NULL;
    BPU_T_Mecs_Ctx *ctx_2 = NULL;
	BPU_T_UN_Mecs_Params params;

    /***************************************/
    // mce initialisation t = 50, m = 11
    fprintf(stderr, "Basic GOPPA Initialisation...\n");
	if (BPU_mecsInitParamsGoppa(&params, 11, 50, 0)) {
		return 1;
	}

	if (BPU_mecsInitCtx(&ctx, &params, BPU_EN_MECS_BASIC_GOPPA)) {
//    if (BPU_mecsInitCtx(&ctx, 11, 50, BPU_EN_MECS_CCA2_POINTCHEVAL_GOPPA)) {
        return 1;
    }
    /***************************************/
    fprintf(stderr, "Key generation...\n");
    // key pair generation
    if (BPU_mecsGenKeyPair(ctx)) {
        BPU_printError("Key generation error");

        return 1;
    }
    rc = BPU_asn1SaveKeyPair(ctx, "prikey.der", "pubkey.der");
    if (rc) {
        asn1_perror(rc);
    }
    rc = BPU_asn1LoadKeyPair(&ctx_2, "prikey.der", "pubkey.der");
    if (rc) {
        asn1_perror(rc);
    }
    testCmpMecsCtx(ctx, ctx_2);

    BPU_mecsFreeCtx(&ctx);
    BPU_mecsFreeCtx(&ctx_2);
	BPU_mecsFreeParamsGoppa(&params);
    return rc;
}
#endif

int main(int argc, char **argv) {
	int rc = 0;
    // MUST BE NULL
    BPU_T_Mecs_Ctx *ctx = NULL;
	BPU_T_UN_Mecs_Params params;

	srand(time(NULL));
#if !defined(BPU_CONF_GOPPA_WO_H) && defined(BPU_CONF_ASN1)
	testKeyGenAsn1();
#endif

//  /***************************************/
//     // mce initialisation t = 50, m = 11
    fprintf(stderr, "Basic GOPPA Initialisation...\n");
    if (BPU_mecsInitParamsGoppa(&params, 11, 50, 0)) {
        return 1;
    }
    if (BPU_mecsInitCtx(&ctx, &params, BPU_EN_MECS_BASIC_GOPPA)) {
        return 1;
    }
    rc += testKeyGenEncDec(ctx);
    BPU_mecsFreeCtx(&ctx);

#ifdef BPU_CONF_MECS_CCA2_POINTCHEVAL_GOPPA
    fprintf(stderr, "\nCCA2 Pointcheval GOPPA Initialisation...\n");
    if (BPU_mecsInitCtx(&ctx, &params, BPU_EN_MECS_CCA2_POINTCHEVAL_GOPPA)) {
        return 1;
    }
    rc += testKeyGenEncDec(ctx);
    BPU_mecsFreeCtx(&ctx);
    BPU_mecsFreeParamsGoppa(&params);
#endif

/*#ifdef BPU_CONF_MECS_CCA2_KOBARA_IMAI_GOPPA
    fprintf(stderr, "\nCCA2 Kobara-IMAI GOPPA Initialisation...\n");
    if (BPU_mecsInitCtx(&ctx, &params, BPU_EN_MECS_CCA2_KOBARA_IMAI_GOPPA)) {
        return 1;
    }
    rc += testKeyGenEncDec(ctx);
    BPU_mecsFreeCtx(&ctx);
    BPU_mecsFreeParamsGoppa(&params);
#endif*/

// 	/***************************************/
//     mce initialisation of 80-bit security
     fprintf(stderr, "Basic QC-MDPC Initialisation...\n");
     if (BPU_mecsInitParamsQcmdpc(&params, 4801, 2, 90, 84)) {
         return 1;
     }
     if (BPU_mecsInitCtx(&ctx, &params, BPU_EN_MECS_BASIC_QCMDPC)) {
         return 1;
     }
     rc += testKeyGenEncDec(ctx);
     BPU_mecsFreeCtx(&ctx);
     BPU_mecsFreeParamsQcmdpc(&params);

 #ifdef BPU_CONF_MECS_CCA2_POINTCHEVAL_GOPPA
     fprintf(stderr, "\nCCA2 Pointcheval QC-MDPC Initialisation...\n");
     if (BPU_mecsInitParamsQcmdpc(&params, 4801, 2, 90, 84)) {
         return 1;
     }
     if (BPU_mecsInitCtx(&ctx, &params, BPU_EN_MECS_CCA2_POINTCHEVAL_QCMDPC)) {
         return 1;
     }
     rc += testKeyGenEncDec(ctx);
     BPU_mecsFreeCtx(&ctx);
     BPU_mecsFreeParamsQcmdpc(&params);
 #endif

 #ifdef BPU_CONF_MECS_HYBRID
     rc += testAesEncDec();
     rc += testKDF();
     rc += testMAC();
     rc += testCryptoBox();
 #endif

//#ifdef BPU_CONF_MECS_EXCHANGE
//   rc += testKeyExchange();
//#endif

	return rc;
}
