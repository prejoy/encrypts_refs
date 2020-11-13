/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_SHA_H
# define HEADER_SHA_H

# include <stddef.h>

#ifdef  __cplusplus
extern "C" {
#endif


#define DATA_ORDER_IS_BIG_ENDIAN
#if defined(DATA_ORDER_IS_BIG_ENDIAN)

# ifndef HOST_c2l
#  define HOST_c2l(c,l)  (l =(((unsigned int)(*((c)++)))<<24),         \
                         l|=(((unsigned int)(*((c)++)))<<16),          \
                         l|=(((unsigned int)(*((c)++)))<< 8),          \
                         l|=(((unsigned int)(*((c)++)))    )           )
# endif
# ifndef HOST_l2c
#  define HOST_l2c(l,c)  (*((c)++)=(unsigned char)(((l)>>24)&0xff),     \
                         *((c)++)=(unsigned char)(((l)>>16)&0xff),      \
                         *((c)++)=(unsigned char)(((l)>> 8)&0xff),      \
                         *((c)++)=(unsigned char)(((l)    )&0xff),      \
                         l)
# endif

#elif defined(DATA_ORDER_IS_LITTLE_ENDIAN)

# ifndef HOST_c2l
#  define HOST_c2l(c,l)  (l =(((unsigned int)(*((c)++)))    ),         \
                         l|=(((unsigned int)(*((c)++)))<< 8),          \
                         l|=(((unsigned int)(*((c)++)))<<16),          \
                         l|=(((unsigned int)(*((c)++)))<<24)           )
# endif
# ifndef HOST_l2c
#  define HOST_l2c(l,c)  (*((c)++)=(unsigned char)(((l)    )&0xff),     \
                         *((c)++)=(unsigned char)(((l)>> 8)&0xff),      \
                         *((c)++)=(unsigned char)(((l)>>16)&0xff),      \
                         *((c)++)=(unsigned char)(((l)>>24)&0xff),      \
                         l)
# endif

#endif


# define SHA256_DIGEST_LENGTH    32

/*-
 * !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
 * ! SHA_LONG has to be at least 32 bits wide.                    !
 * !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
 */
	
# define SHA_LONG unsigned int

# define SHA_LBLOCK      16
# define SHA_CBLOCK      (SHA_LBLOCK*4)/* SHA treats input data as a
                                        * contiguous array of 32 bit wide
	                                    * big-endian values. */


# define SHA256_CBLOCK   (SHA_LBLOCK*4)/* SHA-256 treats input data as a
                                        * contiguous array of 32 bit wide
                                        * big-endian values. */

typedef struct SHA256state_st 
{
    SHA_LONG h[8];
    SHA_LONG Nl, Nh;
    SHA_LONG data[16];
    unsigned int num, md_len;
} SHA256_CTX;

int SHA256_Init(SHA256_CTX *c);
int SHA256_Update(SHA256_CTX *c, const void *data, size_t len);
int SHA256_Final(unsigned char *md, SHA256_CTX *c);
unsigned char *SHA256(const unsigned char *d, size_t n, unsigned char *md);

int SHA256_CTX_copy(SHA256_CTX *to, SHA256_CTX *from);

void SHA256_Transform(SHA256_CTX *c, const unsigned char *data);

static void sha256_block_data_order(SHA256_CTX *ctx, const void *in,
                                    size_t num);

void OPENSSL_cleanse(void *ptr, size_t len);

#ifdef  __cplusplus
}
#endif

#endif
