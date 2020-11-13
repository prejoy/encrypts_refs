/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_HMAC_H
# define HEADER_HMAC_H

# include "sha256.h"

# define HMAC_SHA_256_MD_CBLOCK      SHA256_CBLOCK		

#ifdef  __cplusplus
extern "C" {
#endif


typedef struct sha256_hmac_ctx_st 
{
    SHA256_CTX *md_ctx;
    SHA256_CTX *i_ctx;
    SHA256_CTX *o_ctx;
    unsigned int key_length;
    unsigned char key[HMAC_SHA_256_MD_CBLOCK];
}SHA256_HMAC_CTX;


int SHA256_HMAC_Init(SHA256_HMAC_CTX *ctx, const void *key, int len);
int SHA256_HMAC_Update(SHA256_HMAC_CTX *ctx, const unsigned char *data, size_t len);
int SHA256_HMAC_Final(SHA256_HMAC_CTX *ctx, unsigned char *md);


unsigned char *SHA256_HMAC(const void *key, int key_len,
                    const unsigned char *d, size_t n, unsigned char *md);


SHA256_HMAC_CTX *SHA256_HMAC_CTX_new(void);

void SHA256_HMAC_CTX_free(SHA256_HMAC_CTX *ctx);

int SHA256_HMAC_CTX_copy(SHA256_HMAC_CTX *dctx, SHA256_HMAC_CTX *sctx);

int PKCS5_PBKDF2_SHA256_HMAC(const char *pass, unsigned int passlen,
                      const unsigned char *salt, unsigned int saltlen, unsigned int iter,
                      unsigned int keylen, unsigned char *out);

#ifdef  __cplusplus
}
#endif

#endif
