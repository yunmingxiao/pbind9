#pragma once

/*! Simulate PDNS Challenge Cost */

#include <stdbool.h>

#include <isc/buffer.h>
#include <isc/netaddr.h>
#include <isc/task.h>
#include <isc/types.h>

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <assert.h>
#include <unistd.h>

void sub_timespec(struct timespec t1, struct timespec t2, struct timespec *td);
RSA* createPrivateRSA(char* key);
RSA* createPublicRSA(char* key);
int RSASign(  RSA* rsa,
              const unsigned char* Msg,
              size_t MsgLen,
              unsigned char** EncMsg,
              size_t* MsgLenEnc);
int RSAVerifySignature(  RSA* rsa,
                         unsigned char* MsgHash,
                         size_t MsgHashLen,
                         const char* Msg,
                         size_t MsgLen,
                         int* Authentic);
void Base64Encode( const unsigned char* buffer,
                   size_t length,
                   char** base64Text);
size_t calcDecodeLength(const char* b64input);
void Base64Decode(const char* b64message, unsigned char** buffer, size_t* length);
char* signMessage(char* privateKey, char* plainText, int len);
int verifySignature(char* publicKey, char* plainText, char* signatureBase64, int len);
void sim_challenge(int bandwidth, int msg_len, long time_verify_pir);
