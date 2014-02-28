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
  with modifications by pg314 on 2014/02/28 for pedagogic purposes. Those changes
  are in the public domain.
*/

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

#include "hash.h"
#include "sslKeyExchange.h"
#include "tests.h"

#define QBF "The quick brown fox jumps over the lazy dog"
#define QBF_MD5 "9e107d9d372bb6826bd81d3542a419d6"
#define QBF_SHA1 "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12"

extern OSStatus SSLVerifySignedServerKeyExchange(SSLContext *ctx, bool isRsa,
                                                 SSLBuffer signedParams,
                                                 uint8_t *signature, UInt16 signatureLen);


static void SSLAllocBuffer(SSLBuffer *buf, size_t length);
static void SSLFreeBuffer(SSLBuffer *buf);
static const char *hashToString(SSLDigest h);
static void zeroDigest(SSLDigest digest);
static void checkDigest(SSLDigest digest, const char *expected);
static void testHashDigest();
static void testMD5SHA1();
static void testSSLCalculateServerKeyExchangeHash();
static void testSSLVerifySignedServerKeyExchange();

/*
  A mock implementation for testing purposes.
 */
OSStatus
sslRawVerify(SSLContext *ctx,
             SSLPubKey *pubKey,
             const uint8_t *plainText,
             size_t plainTextLen,
             const uint8_t *sig,
             size_t sigLen)
{
        SSLBuffer plainTextBuf;
        SSLDigest digest;
        uint8_t digestBuf[SSL_MD5_DIGEST_LEN];

        plainTextBuf = createSSLBuffer((uint8_t *)plainText, plainTextLen);
        digest = createSSLDigest(digestBuf, sizeof(digestBuf));

        hashDigest1(&SSLHashMD5, &plainTextBuf, &digest);

	return (digest.length != sigLen) || (memcmp(digest.data, sig, sigLen) != 0);
}

static void
SSLAllocBuffer(SSLBuffer *buf, size_t length)
{
	buf->data = malloc(length);
	if (buf->data == NULL) {
                assert(0);
	}
        buf->length = length;
}

static void
SSLFreeBuffer(SSLBuffer *buf)
{
        assert(buf != NULL);
        free(buf->data);
        buf->data = NULL;
        buf->length = 0;
}

static const char *hashToString(SSLDigest digest)
{
        char *result;

        result = calloc(digest.length * 2 + 1, 1);
        for (unsigned int i = 0; i < digest.length; ++i)
                sprintf(result + 2 * i, "%02x", digest.data[i]);
        return result;
}

static void zeroDigest(SSLDigest digest)
{
        memset(digest.data, 0, digest.length);
}

static void checkDigest(SSLDigest digest, const char *expected)
{
        const char *str;
        str = hashToString(digest);
        assert(!strcmp(str, expected));
        free((void *)str);
}

static void testHashDigest()
{
        const char *str = QBF;
        uint8_t buf[SSL_MAX_DIGEST_LEN];
        SSLDigest md5, sha1;

        md5 = createSSLDigest(buf, SSL_MD5_DIGEST_LEN);
        sha1 = createSSLDigest(buf, SSL_SHA1_DIGEST_LEN);
        {
                SSLBuffer data = createSSLBuffer((uint8_t *)str, strlen(str));

                zeroDigest(md5);
                hashDigest1(&SSLHashMD5, &data, &md5);
                checkDigest(md5, QBF_MD5);

                zeroDigest(sha1);
                hashDigest1(&SSLHashSHA1, &data, &sha1);
                checkDigest(sha1, QBF_SHA1);
        }
        {
                SSLBuffer data1 = createSSLBuffer((uint8_t *)str, 10);
                SSLBuffer data2 = createSSLBuffer((uint8_t *)str + 10, strlen(str) - 10);

                zeroDigest(md5);
                hashDigest2(&SSLHashMD5, &data1, &data2, &md5);
                checkDigest(md5, QBF_MD5);

                zeroDigest(sha1);
                hashDigest2(&SSLHashSHA1, &data1, &data2, &sha1);
                checkDigest(sha1, QBF_SHA1);
        }
        {
                SSLBuffer data1 = createSSLBuffer((uint8_t *)str, 10);
                SSLBuffer data2 = createSSLBuffer((uint8_t *)str + 10, 15);
                SSLBuffer data3 = createSSLBuffer((uint8_t *)str + 25, strlen(str) - 25);

                zeroDigest(md5);
                hashDigest3(&SSLHashMD5, &data1, &data2, &data3, &md5);
                checkDigest(md5, QBF_MD5);

                zeroDigest(sha1);
                hashDigest3(&SSLHashSHA1, &data1, &data2, &data3, &sha1);
                checkDigest(sha1, QBF_SHA1);
        }
}

static void testMD5SHA1()
{
        const char *str = QBF;
        uint8_t buf[SSL_MAX_DIGEST_LEN];
        SSLBuffer data;
        SSLDigest md;
        const char *md_str;

        data = createSSLBuffer((uint8_t *)str, strlen(str));
        md = createSSLDigest(buf, SSL_MAX_DIGEST_LEN);
        hashDigest1(&SSLHashMD5SHA1, &data, &md);
        md_str = hashToString(md);
        assert(!strcmp(md_str, QBF_MD5 QBF_SHA1));
        free((void *)md_str);
}

static void testSSLCalculateServerKeyExchangeHash()
{
        size_t len = SSL_CLIENT_SRVR_RAND_SIZE;
        size_t signedParamsLen;
        const char *str = "Thus, programs must be written for people to read,"
                " and only incidentally for machines to execute.";
        SSLContext ctx;
        SSLBuffer signedParams;
        uint8_t md[SSL_MAX_DIGEST_LEN];
        uint8_t buf[1024];
        const char *hash_str;

        memcpy(ctx.clientRandom, str, len);
        memcpy(ctx.serverRandom, str + len, len);
        signedParams.data = buf;
        signedParamsLen = strlen(str) - 2 * len;
        memcpy(signedParams.data, str + 2 * len, signedParamsLen);
        signedParams.length = signedParamsLen;

        SSLCalculateServerKeyExchangeHash(&SSLHashMD5, &ctx, signedParams, md);

        hash_str = hashToString(createSSLDigest(md, SSL_MD5_DIGEST_LEN));
        assert(!strcmp(hash_str, "71dfd198f59ff82b919b94397c064a55"));
        free((void *)hash_str);
}

static void testSSLVerifySignedServerKeyExchange()
{
        const size_t signedParamsLen = 10;
        SSLBuffer signedParams, dataBuffer;
        const size_t len = 2 * SSL_CLIENT_SRVR_RAND_SIZE + signedParamsLen;
        uint8_t data[len];
        SSLContext ctx;

        for (unsigned int i = 0; i < len; ++i) {
                data[i] = (uint8_t)i;
        }

        signedParams.data = data + 2 * SSL_CLIENT_SRVR_RAND_SIZE;
        signedParams.length = signedParamsLen;

        dataBuffer.data = data;
        dataBuffer.length = len;

        ctx.peerPubKey = 0;
        memcpy(ctx.clientRandom, data, SSL_CLIENT_SRVR_RAND_SIZE);
        memcpy(ctx.serverRandom, data + SSL_CLIENT_SRVR_RAND_SIZE, SSL_CLIENT_SRVR_RAND_SIZE);

        {
                OSStatus err;
                uint8_t sigBuf[SSL_MD5_DIGEST_LEN];
                uint8_t sha1Buf[SSL_SHA1_DIGEST_LEN];
                SSLBuffer sha1Data;
                SSLDigest sig, sha1;

                sha1 = createSSLDigest(sha1Buf, sizeof(sha1Buf));
                hashDigest1(&SSLHashSHA1, &dataBuffer, &sha1);

                sha1Data = createSSLBuffer(sha1Buf, sizeof(sha1Buf));
                sig = createSSLDigest(sigBuf, sizeof(sigBuf));
                hashDigest1(&SSLHashMD5, &sha1Data, &sig);

                err = SSLVerifySignedServerKeyExchange(&ctx, 0, signedParams, sig.data, (UInt16)sig.length);
                assert(err == 0);

                sig.data[0] ^= 1;
                err = SSLVerifySignedServerKeyExchange(&ctx, 0, signedParams, sig.data, (UInt16)sig.length);
                assert(err == 1);
        }
        {
                OSStatus err;
                uint8_t sigBuf[SSL_MD5_DIGEST_LEN];
                uint8_t md5Buf[SSL_MD5_DIGEST_LEN];
                uint8_t sha1Buf[SSL_SHA1_DIGEST_LEN];
                SSLDigest sig, md5, sha1;
                SSLBuffer md5Data, sha1Data;

                md5 = createSSLDigest(md5Buf, sizeof(md5Buf));
                sha1 = createSSLDigest(sha1Buf, sizeof(sha1Buf));
                hashDigest1(&SSLHashMD5, &dataBuffer, &md5);
                hashDigest1(&SSLHashSHA1, &dataBuffer, &sha1);

                md5Data = createSSLBuffer(md5Buf, sizeof(md5Buf));
                sha1Data = createSSLBuffer(sha1Buf, sizeof(sha1Buf));
                sig = createSSLDigest(sigBuf, sizeof(sigBuf));
                hashDigest2(&SSLHashMD5, &md5Data, &sha1Data, &sig);

                err = SSLVerifySignedServerKeyExchange(&ctx, 1, signedParams, sig.data, (UInt16)sig.length);
                assert(err == 0);

                sig.data[0] ^= 1;
                err = SSLVerifySignedServerKeyExchange(&ctx, 0, signedParams, sig.data, (UInt16)sig.length);
                assert(err == 1);
        }
}


void tests()
{
        testHashDigest();
        testMD5SHA1();
        testSSLCalculateServerKeyExchangeHash();
        testSSLVerifySignedServerKeyExchange();
        fprintf(stderr, "ok\n");
}

unsigned long long get_usecs()
{
        struct timeval now;
        gettimeofday(&now, NULL);
        return now.tv_usec + (unsigned long long)now.tv_sec * 1000000;
}

void timeHashDigest(unsigned int n)
{
        const char *str = QBF;
        SSLBuffer data1, data2;

        data1 = createSSLBuffer((uint8_t *)str, 10);
        data2 = createSSLBuffer((uint8_t *)str + 10, strlen(str) - 10);

        {
                unsigned long long t0, t1;

                t0 = get_usecs();
                {
                        SSLDigest md5;
                        unsigned char md5Buf[16];
                        md5 = createSSLDigest(md5Buf, sizeof(md5Buf));
                        for (int i = 0; i < n; ++i)
                                hashDigest2(&SSLHashMD5, &data1, &data2, &md5);
                        checkDigest(md5, QBF_MD5);
                }
                {
                        SSLDigest sha1;
                        unsigned char sha1Buf[20];
                        sha1 = createSSLDigest(sha1Buf, sizeof(sha1Buf));
                        for (int i = 0; i < n; ++i)
                                hashDigest2(&SSLHashSHA1, &data1, &data2, &sha1);
                        checkDigest(sha1, QBF_SHA1);
                }
                t1 = get_usecs();
                fprintf(stderr, "%d * hashDigest2: %llu ms.\n", n, (t1 - t0) / 1000);
        }
        {
                unsigned long long t0, t1;
                t0 = get_usecs();
                {
                        SSLDigest md5;
                        unsigned char md5Buf[16];
                        md5 = createSSLDigest(md5Buf, sizeof(md5Buf));
                        for (int i = 0; i < n; ++i) {
                                SSLBuffer state;
                                SSLAllocBuffer(&state, SSLHashMD5.contextSize);
                                SSLHashMD5.init(&state);
                                SSLHashMD5.update(&state, &data1);
                                SSLHashMD5.update(&state, &data2);
                                SSLHashMD5.final(&state, &md5);
                                SSLFreeBuffer(&state);
                        }
                        checkDigest(md5, QBF_MD5);
                }
                {
                        SSLDigest sha1;
                        unsigned char sha1Buf[20];

                        sha1 = createSSLDigest(sha1Buf, sizeof(sha1Buf));
                        for (int i = 0; i < n; ++i) {
                                SSLBuffer state;
                                SSLAllocBuffer(&state, SSLHashSHA1.contextSize);
                                SSLHashSHA1.init(&state);
                                SSLHashSHA1.update(&state, &data1);
                                SSLHashSHA1.update(&state, &data2);
                                SSLHashSHA1.final(&state, &sha1);
                                SSLFreeBuffer(&state);
                        }
                        checkDigest(sha1, QBF_SHA1);
                }
                t1 = get_usecs();
                fprintf(stderr, "%d * init/update/final: %llu ms.\n", n, (t1 - t0) / 1000);
        }
}
