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

#define SSL_SHA1_DIGEST_LEN 20
#define SSL_MD5_DIGEST_LEN 16
#define SSL_MAX_DIGEST_LEN (SSL_SHA1_DIGEST_LEN + SSL_MD5_DIGEST_LEN)
#define SSL_CLIENT_SRVR_RAND_SIZE 32

#define sslErrorLog(...)

typedef int32_t OSStatus;
typedef uint32_t UInt32;
typedef uint16_t UInt16;
typedef int SSLPubKey;

typedef struct {
        SSLPubKey *peerPubKey;
        uint8_t clientRandom[SSL_CLIENT_SRVR_RAND_SIZE];
        uint8_t serverRandom[SSL_CLIENT_SRVR_RAND_SIZE];
} SSLContext;

OSStatus sslRawVerify(SSLContext *ctx,
                      SSLPubKey *pubKey,
                      const uint8_t *plainText,
                      size_t plainTextLen,
                      const uint8_t *sig,
                      size_t sigLen);
void
SSLCalculateServerKeyExchangeHash(const HashReference *hash,
                                  SSLContext *ctx, SSLBuffer signedParams,
                                  uint8_t buf[SSL_MAX_DIGEST_LEN]);
OSStatus SSLVerifySignedServerKeyExchange(SSLContext *ctx, bool isRsa,
                                          SSLBuffer signedParams,
                                          uint8_t *signature, UInt16 signatureLen);
