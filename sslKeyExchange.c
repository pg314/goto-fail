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
#include <stdlib.h>

#include "hash.h"
#include "sslKeyExchange.h"

void
SSLCalculateServerKeyExchangeHash(const HashReference *hash,
                                  SSLContext *ctx, SSLBuffer signedParams,
                                  uint8_t buf[SSL_MAX_DIGEST_LEN])
{
        SSLBuffer clientRandom, serverRandom;
        SSLDigest md;

        assert(hash->digestSize <= SSL_MAX_DIGEST_LEN);

        clientRandom = createSSLBuffer(ctx->clientRandom, SSL_CLIENT_SRVR_RAND_SIZE);
        serverRandom = createSSLBuffer(ctx->serverRandom, SSL_CLIENT_SRVR_RAND_SIZE);
        md = createSSLDigest(buf, hash->digestSize);
        hashDigest3(hash, &clientRandom, &serverRandom, &signedParams, &md);
}

OSStatus
SSLVerifySignedServerKeyExchange(SSLContext *ctx, bool isRsa, SSLBuffer signedParams,
                                 uint8_t *signature, UInt16 signatureLen)
{
        OSStatus err;
        uint8_t buf[SSL_MAX_DIGEST_LEN];
        const HashReference *hash;

        hash = isRsa ? &SSLHashMD5SHA1 : &SSLHashSHA1;

        SSLCalculateServerKeyExchangeHash(hash, ctx, signedParams, buf);

	err = sslRawVerify(ctx,
                           ctx->peerPubKey,
                           buf,
                           hash->digestSize,
                           signature,
                           signatureLen);
	if (err) {
		sslErrorLog("SSLVerifySignedServerKeyExchange: sslRawVerify "
                            "returned %d\n", (int)err);
	}
        return err;
}
