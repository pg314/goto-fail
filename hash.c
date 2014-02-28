// -*- c-basic-offset: 8 -*-

/*
  Portions Copyright (c) 1999-2007 Apple Inc.  All Rights Reserved.

  This file contains Original Code and/or Modifications of Original Code as
  defined in and that are subject to the Apple Public Source License Version 2.0
  (the 'License').  You may not use this file except in compliance with the
  License.  Please obtain a copy of the License at
  http://www.opensource.apple.com/apsl/ and read it before using this file.

  The Original Code and all software distributed under the License are
  distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESS
  OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES, INCLUDING WITHOUT
  LIMITATION, ANY WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
  PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.  Please see the License for the
  specific language governing rights and limitations under the License.

  Downloaded from http://opensource.apple.com/source/Security/Security-55471/
  with modifications by pg314 on 2014/02/28 for pedagogic purposes.  Those changes
  are in the public domain.
*/

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>

/*
  You can use OpenSSL i.s.o. CommonCrypto by defining -DUSE_OPENSSL and linking -lcrypto.
  E.g.
  CFLAGS=-DUSE_OPENSSL LDFLAGS=-lcrypto make

  Perhaps surprisingly, OpenSSL is faster than CommonCrypto on my computer:
  $ time ./hash 1000000
  1000000 * hashDigest2: 695 ms.
  1000000 * init/update/final: 860 ms.

  On Linux in VirtualBox on the same machine it takes 450 ms and 520 ms (different
  version of OpenSSL, or compiled with different optimization settings).

  Maybe because of the overhead of calling CommonCrypto? The data to hash is small.
*/

#if defined(__APPLE__) && !defined(USE_OPENSSL)

#include <CommonCrypto/CommonDigest.h>
#define MD5_DIGEST_LENGTH CC_MD5_DIGEST_LENGTH
#define MD5_CTX CC_MD5_CTX
#define MD5_Init CC_MD5_Init
#define MD5_Update CC_MD5_Update
#define MD5_Final CC_MD5_Final

#define SHA1_DIGEST_LENGTH CC_SHA1_DIGEST_LENGTH
#define SHA1_CTX CC_SHA1_CTX
#define SHA1_Init CC_SHA1_Init
#define SHA1_Update CC_SHA1_Update
#define SHA1_Final CC_SHA1_Final

#else

#include <openssl/md5.h>
#include <openssl/sha.h>

#define SHA1_CTX SHA_CTX
#define SHA1_DIGEST_LENGTH SHA_DIGEST_LENGTH

#endif

#include "hash.h"

static int fitsInUint32(size_t x);
static void HashMD5Init(SSLBuffer *digestCtx);
static void HashMD5Update(SSLBuffer *digestCtx, const SSLBuffer *data);
static void HashMD5Final(SSLBuffer *digestCtx, SSLDigest *md);
static void HashMD5Digest(SSLBuffer **bufs, unsigned int len, SSLDigest *md);
static void HashSHA1Init(SSLBuffer *digestCtx);
static void HashSHA1Update(SSLBuffer *digestCtx, const SSLBuffer *data);
static void HashSHA1Final(SSLBuffer *digestCtx, SSLDigest *md);
static void HashSHA1Digest(SSLBuffer **bufs, unsigned int len, SSLDigest *md);
static void HashMD5SHA1Digest(SSLBuffer **bufs, unsigned int len, SSLDigest *md);

const HashReference SSLHashMD5 = {
        MD5_DIGEST_LENGTH,
        sizeof(MD5_CTX),
        HashMD5Init,
        HashMD5Update,
        HashMD5Final,
        HashMD5Digest
};

const HashReference SSLHashSHA1 = {
        SHA1_DIGEST_LENGTH,
        sizeof(SHA1_CTX),
        HashSHA1Init,
        HashSHA1Update,
        HashSHA1Final,
        HashSHA1Digest
};

const HashReference SSLHashMD5SHA1 = {
        .digestSize = MD5_DIGEST_LENGTH + SHA1_DIGEST_LENGTH,
        0,
        NULL,
        NULL,
        NULL,
        .digest = HashMD5SHA1Digest
};

SSLBuffer
createSSLBuffer(uint8_t *data, size_t len)
{
        return (SSLBuffer){ len, data };
}

SSLDigest
createSSLDigest(uint8_t *data, size_t len)
{
        return (SSLDigest){ len, data };
}

static int fitsInUint32(size_t x)
{
        return x == (uint32_t)x;
}

static void HashMD5Init(SSLBuffer *digestCtx)
{
	assert(digestCtx->length >= sizeof(MD5_CTX));

	MD5_CTX *ctx = (MD5_CTX *)digestCtx->data;
	MD5_Init(ctx);
}

static void HashMD5Update(SSLBuffer *digestCtx, const SSLBuffer *data)
{
        /* 64 bits cast: safe, SSL records are always smaller than 2^32 bytes */
	assert(digestCtx->length >= sizeof(MD5_CTX));

	MD5_CTX *ctx = (MD5_CTX *)digestCtx->data;
	MD5_Update(ctx, data->data, (uint32_t)data->length);
}

static void HashMD5Final(SSLBuffer *digestCtx, SSLDigest *md)
{
	assert(digestCtx->length >= sizeof(MD5_CTX));

	MD5_CTX *ctx = (MD5_CTX *)digestCtx->data;
	assert(md->length >= MD5_DIGEST_LENGTH);
	MD5_Final(md->data, ctx);
	md->length = MD5_DIGEST_LENGTH;
}

static void HashMD5Digest(SSLBuffer **bufs, unsigned int len, SSLDigest *md)
{
        MD5_CTX ctx;

        assert(md->length >= MD5_DIGEST_LENGTH);

        MD5_Init(&ctx);
        for (unsigned int i = 0; i < len; ++i) {
                SSLBuffer *buf = bufs[i];
                assert(fitsInUint32(buf->length));
                MD5_Update(&ctx, buf->data, (uint32_t)buf->length);
        }
        MD5_Final(md->data, &ctx);
}

static void HashSHA1Init(SSLBuffer *digestCtx)
{
	assert(digestCtx->length >= sizeof(SHA1_CTX));

	SHA1_CTX *ctx = (SHA1_CTX *)digestCtx->data;
	SHA1_Init(ctx);
}

static void HashSHA1Update(SSLBuffer *digestCtx, const SSLBuffer *data)
{
        /* 64 bits cast: safe, SSL records are always smaller than 2^32 bytes */
	assert(digestCtx->length >= sizeof(SHA1_CTX));

	SHA1_CTX *ctx = (SHA1_CTX *)digestCtx->data;
	SHA1_Update(ctx, data->data, (uint32_t)data->length);
}

static void HashSHA1Final(SSLBuffer *digestCtx, SSLDigest *md)
{
	assert(digestCtx->length >= sizeof(SHA1_CTX));
	assert(md->length >= SHA1_DIGEST_LENGTH);

	SHA1_CTX *ctx = (SHA1_CTX *)digestCtx->data;
	SHA1_Final(md->data, ctx);
	md->length = SHA1_DIGEST_LENGTH;
}

static void
HashSHA1Digest(SSLBuffer **bufs, unsigned int len, SSLDigest *md)
{
        SHA1_CTX ctx;

        assert(md->length >= SHA1_DIGEST_LENGTH);

        SHA1_Init(&ctx);
        for (unsigned int i = 0; i < len; ++i) {
                SSLBuffer *buf = bufs[i];
                assert(fitsInUint32(buf->length));
                SHA1_Update(&ctx, buf->data, (uint32_t)buf->length);
        }
        SHA1_Final(md->data, &ctx);
}

static void
HashMD5SHA1Digest(SSLBuffer **bufs, unsigned int len, SSLDigest *md)
{
        uint32_t md5Len;
        SSLDigest md5, sha1;

        assert(md->length >= SSLHashMD5SHA1.digestSize);

        md5Len = SSLHashMD5.digestSize;

        md5 = createSSLDigest(md->data, md5Len);
        SSLHashMD5.digest(bufs, len, &md5);

        sha1 = createSSLDigest(md->data + md5Len, SSLHashSHA1.digestSize);
        SSLHashSHA1.digest(bufs, len, &sha1);
}

void
hashDigest1(const HashReference *h, SSLBuffer *d, SSLDigest *md)
{
        h->digest(&d, 1, md);
}

void
hashDigest2(const HashReference *h, SSLBuffer *d1, SSLBuffer *d2, SSLDigest *md)
{
        SSLBuffer *buffers[2] = { d1, d2 };
        h->digest(buffers, 2, md);
}

void
hashDigest3(const HashReference *h, SSLBuffer *d1, SSLBuffer *d2, SSLBuffer *d3, SSLDigest *md)
{
        SSLBuffer *buffers[3] = { d1, d2, d3 };
        h->digest(buffers, 3, md);
}
