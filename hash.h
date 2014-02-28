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

typedef struct {
        size_t length;
        uint8_t *data;
} SSLBuffer;

typedef struct {
        size_t length;
        uint8_t *data;
} SSLDigest;

typedef void (*HashInit)(SSLBuffer *digestCtx);
typedef void (*HashUpdate)(SSLBuffer *digestCtx, const SSLBuffer *data);
typedef void (*HashFinal)(SSLBuffer *digestCtx, SSLDigest *md);
typedef void (*HashDigest)(SSLBuffer **bufs, unsigned int len, SSLDigest *md);

typedef struct {
        uint32_t digestSize;
        uint32_t contextSize;
        HashInit init;
        HashUpdate update;
        HashFinal final;
        HashDigest digest;
} HashReference;

SSLBuffer createSSLBuffer(uint8_t *data, size_t len);
SSLDigest createSSLDigest(uint8_t *data, size_t len);

void hashDigest1(const HashReference *, SSLBuffer *, SSLDigest *);
void hashDigest2(const HashReference *, SSLBuffer *, SSLBuffer *, SSLDigest *);
void hashDigest3(const HashReference *, SSLBuffer *, SSLBuffer *, SSLBuffer *, SSLDigest *);

extern const HashReference SSLHashMD5;
extern const HashReference SSLHashSHA1;
extern const HashReference SSLHashMD5SHA1;
