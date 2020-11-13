/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "hmac.h"



int SHA256_HMAC_Init(SHA256_HMAC_CTX *ctx, const void *key, int len)
{
    int i, reset = 0;
    unsigned char pad[SHA256_CBLOCK];

    /* If we are changing MD then we must have a key */
    if (ctx == NULL || key == NULL || len < 0)
        return 0;

 	if (SHA256_CBLOCK < len) 
	{
		if (!SHA256_Init(ctx->md_ctx))
			goto err;
		if (!SHA256_Update(ctx->md_ctx, key, len))
			goto err;
		if (!SHA256_Final(ctx->key, ctx->md_ctx))
			goto err;
		ctx->key_length = SHA256_DIGEST_LENGTH;
	} 
	else 
	{
		 memcpy(ctx->key, key, len);
		ctx->key_length = len;
	}
	
	if (ctx->key_length != SHA256_CBLOCK)
		memset(&ctx->key[ctx->key_length], 0, SHA256_CBLOCK - ctx->key_length);

	for (i = 0; i < SHA256_CBLOCK; i++)
		pad[i] = 0x36 ^ ctx->key[i];
	if (!SHA256_Init(ctx->i_ctx))
		goto err;
	if (!SHA256_Update(ctx->i_ctx, pad, SHA256_CBLOCK))
		goto err;

	for (i = 0; i < SHA256_CBLOCK; i++)
		pad[i] = 0x5c ^ ctx->key[i];
	if (!SHA256_Init(ctx->o_ctx))
		goto err;
	if (!SHA256_Update(ctx->o_ctx, pad, SHA256_CBLOCK))
		goto err;

    if (!SHA256_CTX_copy(ctx->md_ctx, ctx->i_ctx))
        goto err;
    return 1;
 err:
    return 0;
}


int SHA256_HMAC_Update(SHA256_HMAC_CTX *ctx, const unsigned char *data, size_t len)
{
    if (!ctx->md_ctx)
        return 0;
    return SHA256_Update(ctx->md_ctx, data, len);
}

int SHA256_HMAC_Final(SHA256_HMAC_CTX *ctx, unsigned char *md)
{
    unsigned char buf[SHA256_DIGEST_LENGTH];

    if (!ctx->md_ctx)
        goto err;

    if (!SHA256_Final(buf, ctx->md_ctx))
        goto err;
    if (!SHA256_CTX_copy(ctx->md_ctx, ctx->o_ctx))
        goto err;
    if (!SHA256_Update(ctx->md_ctx, buf, SHA256_DIGEST_LENGTH))
        goto err;
    if (!SHA256_Final(md, ctx->md_ctx))
        goto err;
    return 1;
 err:
    return 0;
}

SHA256_HMAC_CTX *SHA256_HMAC_CTX_new(void)
{
    SHA256_HMAC_CTX *ctx = (SHA256_HMAC_CTX *)malloc(sizeof(SHA256_HMAC_CTX));		

	ctx->md_ctx = (SHA256_CTX *)malloc(sizeof(SHA256_CTX));		
    ctx->i_ctx = (SHA256_CTX *)malloc(sizeof(SHA256_CTX));		
    ctx->o_ctx = (SHA256_CTX *)malloc(sizeof(SHA256_CTX));		

    return ctx;
}

void SHA256_HMAC_CTX_free(SHA256_HMAC_CTX *ctx)
{
    if (ctx != NULL) 
	{
        memset(ctx->md_ctx, 0, sizeof(SHA256_CTX));
		memset(ctx->i_ctx, 0, sizeof(SHA256_CTX));
        memset(ctx->o_ctx, 0, sizeof(SHA256_CTX));
        free(ctx->md_ctx);
        free(ctx->i_ctx);
        free(ctx->o_ctx);
		memset(ctx, 0, sizeof(SHA256_HMAC_CTX));
        free(ctx);
    }
}


int SHA256_HMAC_CTX_reset(SHA256_HMAC_CTX *ctx)
{
    if (ctx != NULL) 
	{
        memset(ctx->md_ctx, 0, sizeof(SHA256_CTX));
		memset(ctx->i_ctx, 0, sizeof(SHA256_CTX));
        memset(ctx->o_ctx, 0, sizeof(SHA256_CTX));
		memset(ctx->key, 0, sizeof(HMAC_SHA_256_MD_CBLOCK));
		ctx->key_length = 0;
		
		return 1;
    }
	else
		return 0;
}


int SHA256_HMAC_CTX_copy(SHA256_HMAC_CTX *dctx, SHA256_HMAC_CTX *sctx)
{
	if(dctx == NULL || sctx == NULL)
		return 0;

	dctx->key_length = sctx->key_length;
	memcpy(dctx->md_ctx, sctx->md_ctx, sizeof(SHA256_CTX));
	memcpy(dctx->i_ctx, sctx->i_ctx, sizeof(SHA256_CTX));
	memcpy(dctx->o_ctx, sctx->o_ctx, sizeof(SHA256_CTX));
	memcpy(dctx->key, sctx->key, HMAC_SHA_256_MD_CBLOCK);

	return 1;
}


unsigned char *SHA256_HMAC(const void *key, int key_len, const unsigned char *d, size_t n, unsigned char *md)
{
    SHA256_HMAC_CTX *c = NULL;
	static unsigned char m[SHA256_DIGEST_LENGTH];
    static const unsigned char dummy_key[1] = {'\0'};

    if (md == NULL)
        md = m;
    if ((c = SHA256_HMAC_CTX_new()) == NULL)
        goto err;

    /* For HMAC_Init, NULL key signals reuse. */
    if (key == NULL && key_len == 0) {
        key = dummy_key;
    }

    if (!SHA256_HMAC_Init(c, key, key_len))
        goto err;
    if (!SHA256_HMAC_Update(c, d, n))
        goto err;
    if (!SHA256_HMAC_Final(c, md))
        goto err;
	   
    SHA256_HMAC_CTX_free(c);
    return md;
 err:
    SHA256_HMAC_CTX_free(c);
    return NULL;
}


/*
 * This is an implementation of PKCS#5 v2.0 password based encryption key
 * derivation function PBKDF2. SHA1 version verified against test vectors
 * posted by Peter Gutmann <pgut001@cs.auckland.ac.nz> to the PKCS-TNG
 * <pkcs-tng@rsa.com> mailing list.
 */

int PKCS5_PBKDF2_SHA256_HMAC(const char *pass, unsigned int passlen,
                      const unsigned char *salt, unsigned int saltlen, unsigned int iter,
                      unsigned int keylen, unsigned char *out)
{
    const char *empty = "";
    unsigned char digtmp[SHA256_CBLOCK], itmp[4];
    int cplen, j, k;
    unsigned int i = 1;
    SHA256_HMAC_CTX *hctx_tpl = NULL, *hctx = NULL;

	if (pass == NULL) {
        pass = empty;
        passlen = 0;
    } 

	if(!iter && !keylen)
		return 0;

    hctx_tpl = SHA256_HMAC_CTX_new();
    if (hctx_tpl == NULL)
        return 0;

    if (!SHA256_HMAC_Init(hctx_tpl, pass, passlen)) {
        SHA256_HMAC_CTX_free(hctx_tpl);
        return 0;
    }
    hctx = SHA256_HMAC_CTX_new();
    if (hctx == NULL) {
        SHA256_HMAC_CTX_free(hctx_tpl);
        return 0;
    }
    while (keylen) {

		cplen = (keylen > SHA256_DIGEST_LENGTH) ? SHA256_DIGEST_LENGTH : keylen;

        /*
         * We are unlikely to ever use more than 256 blocks (5120 bits!) but
         * just in case...
         */
        itmp[0] = (unsigned char)((i >> 24) & 0xff);
        itmp[1] = (unsigned char)((i >> 16) & 0xff);
        itmp[2] = (unsigned char)((i >> 8) & 0xff);
        itmp[3] = (unsigned char)(i & 0xff);
        if (!SHA256_HMAC_CTX_copy(hctx, hctx_tpl)) {
            SHA256_HMAC_CTX_free(hctx);
            SHA256_HMAC_CTX_free(hctx_tpl);
            return 0;
        }
        if (!SHA256_HMAC_Update(hctx, salt, saltlen)
            || !SHA256_HMAC_Update(hctx, itmp, 4)
            || !SHA256_HMAC_Final(hctx, digtmp)) {
            SHA256_HMAC_CTX_free(hctx);
            SHA256_HMAC_CTX_free(hctx_tpl);
            return 0;
        }
        SHA256_HMAC_CTX_reset(hctx);
        memcpy(out, digtmp, cplen);
        for (j = 1; j < iter; j++) {
            if (!SHA256_HMAC_CTX_copy(hctx, hctx_tpl)) {
                SHA256_HMAC_CTX_free(hctx);
                SHA256_HMAC_CTX_free(hctx_tpl);
                return 0;
            }
            if (!SHA256_HMAC_Update(hctx, digtmp, SHA256_DIGEST_LENGTH)
                || !SHA256_HMAC_Final(hctx, digtmp)) {
                SHA256_HMAC_CTX_free(hctx);
                SHA256_HMAC_CTX_free(hctx_tpl);
                return 0;
            }
            SHA256_HMAC_CTX_reset(hctx);
            for (k = 0; k < cplen; k++)
                out[k] ^= digtmp[k];
        }
        keylen -= cplen;
        i++;
        out += cplen;
    }
    SHA256_HMAC_CTX_free(hctx);
    SHA256_HMAC_CTX_free(hctx_tpl);

    return 1;
}