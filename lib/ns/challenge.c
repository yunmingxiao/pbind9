#include <ns/challenge.h>

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

enum { NS_PER_SECOND = 1000000000 };

void sub_timespec(struct timespec t1, struct timespec t2, struct timespec *td)
{
    td->tv_nsec = t2.tv_nsec - t1.tv_nsec;
    td->tv_sec  = t2.tv_sec - t1.tv_sec;
    if (td->tv_sec > 0 && td->tv_nsec < 0)
    {
        td->tv_nsec += NS_PER_SECOND;
        td->tv_sec--;
    }
    else if (td->tv_sec < 0 && td->tv_nsec > 0)
    {
        td->tv_nsec -= NS_PER_SECOND;
        td->tv_sec++;
    }
}

RSA* createPrivateRSA(char* key) {
  RSA *rsa = NULL;
  const char* c_string = key;
  BIO * keybio = BIO_new_mem_buf((void*)c_string, -1);
  if (keybio==NULL) {
      return 0;
  }
  rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa,NULL, NULL);
  return rsa;
}

RSA* createPublicRSA(char* key) {
  RSA *rsa = NULL;
  BIO *keybio;
  const char* c_string = key;
  keybio = BIO_new_mem_buf((void*)c_string, -1);
  if (keybio==NULL) {
      return 0;
  }
  rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa,NULL, NULL);
  return rsa;
}

int RSASign( RSA* rsa,
              const unsigned char* Msg,
              size_t MsgLen,
              unsigned char** EncMsg,
              size_t* MsgLenEnc) {
  EVP_MD_CTX* m_RSASignCtx = EVP_MD_CTX_create();
  EVP_PKEY* priKey  = EVP_PKEY_new();
  EVP_PKEY_assign_RSA(priKey, rsa);
  if (EVP_DigestSignInit(m_RSASignCtx,NULL, EVP_sha256(), NULL,priKey)<=0) {
      return 0;
  }
  if (EVP_DigestSignUpdate(m_RSASignCtx, Msg, MsgLen) <= 0) {
      return 0;
  }
  if (EVP_DigestSignFinal(m_RSASignCtx, NULL, MsgLenEnc) <=0) {
      return 0;
  }
  *EncMsg = (unsigned char*)malloc(*MsgLenEnc);
  if (EVP_DigestSignFinal(m_RSASignCtx, *EncMsg, MsgLenEnc) <= 0) {
      return 0;
  }
  //EVP_MD_CTX_cleanup(m_RSASignCtx);
  return 1;
}

int RSAVerifySignature( RSA* rsa,
                         unsigned char* MsgHash,
                         size_t MsgHashLen,
                         const char* Msg,
                         size_t MsgLen,
                         int* Authentic) {
  *Authentic = 1;
  EVP_PKEY* pubKey  = EVP_PKEY_new();
  EVP_PKEY_assign_RSA(pubKey, rsa);
  EVP_MD_CTX* m_RSAVerifyCtx = EVP_MD_CTX_create();

  if (EVP_DigestVerifyInit(m_RSAVerifyCtx,NULL, EVP_sha256(),NULL,pubKey)<=0) {
    return 0;
  }
  if (EVP_DigestVerifyUpdate(m_RSAVerifyCtx, Msg, MsgLen) <= 0) {
    return 0;
  }
  int AuthStatus = EVP_DigestVerifyFinal(m_RSAVerifyCtx, MsgHash, MsgHashLen);
  if (AuthStatus==1) {
    *Authentic = 1;
    //EVP_MD_CTX_cleanup(m_RSAVerifyCtx);
    return 1;
  } else if(AuthStatus==0){
    *Authentic = 0;
    //EVP_MD_CTX_cleanup(m_RSAVerifyCtx);
    return 1;
  } else{
    *Authentic = 0;
    //EVP_MD_CTX_cleanup(m_RSAVerifyCtx);
    return 0;
  }
}

void Base64Encode( const unsigned char* buffer,
                   size_t length,
                   char** base64Text) {
  BIO *bio, *b64;
  BUF_MEM *bufferPtr;

  b64 = BIO_new(BIO_f_base64());
  bio = BIO_new(BIO_s_mem());
  bio = BIO_push(b64, bio);

  BIO_write(bio, buffer, length);
  BIO_flush(bio);
  BIO_get_mem_ptr(bio, &bufferPtr);
  BIO_set_close(bio, BIO_NOCLOSE);
  BIO_free_all(bio);

  *base64Text=(*bufferPtr).data;
}

size_t calcDecodeLength(const char* b64input) {
  size_t len = strlen(b64input), padding = 0;

  if (b64input[len-1] == '=' && b64input[len-2] == '=') //last two chars are =
    padding = 2;
  else if (b64input[len-1] == '=') //last char is =
    padding = 1;
  return (len*3)/4 - padding;
}

void Base64Decode(const char* b64message, unsigned char** buffer, size_t* length) {
  BIO *bio, *b64;

  int decodeLen = calcDecodeLength(b64message);
  *buffer = (unsigned char*)malloc(decodeLen + 1);
  (*buffer)[decodeLen] = '\0';

  bio = BIO_new_mem_buf(b64message, -1);
  b64 = BIO_new(BIO_f_base64());
  bio = BIO_push(b64, bio);

  *length = BIO_read(bio, *buffer, strlen(b64message));
  BIO_free_all(bio);
}

char* signMessage(char* privateKey, char* plainText, int len) {
  RSA* privateRSA = createPrivateRSA(privateKey); 
  unsigned char* encMessage;
  char* base64Text;
  size_t encMessageLength;
  RSASign(privateRSA, (unsigned char*) plainText, len, &encMessage, &encMessageLength);
  Base64Encode(encMessage, encMessageLength, &base64Text);
  free(encMessage);
  return base64Text;
}

int verifySignature(char* publicKey, char* plainText, char* signatureBase64, int len) {
  RSA* publicRSA = createPublicRSA(publicKey);
  unsigned char* encMessage;
  size_t encMessageLength;
  int authentic;
  Base64Decode(signatureBase64, &encMessage, &encMessageLength);
  int result = RSAVerifySignature(publicRSA, encMessage, encMessageLength, plainText, len, &authentic);
  return result & authentic;
}


void sim_challenge(int bandwidth, int msg_len, double time_verify_pir) {
  struct timespec start, end;
  useconds_t tt_recv_msg_mus = (msg_len * 1024 * 8) / bandwidth;
  usleep(tt_recv_msg_mus);
  
  int len = 39*1024;
  char plainText[39*1024+1];
  for(int i = 0; i < len; ++i) {
    plainText[i] = 'x';
  }
  plainText[len] = '\0';
  
  char privateKey[] ="-----BEGIN RSA PRIVATE KEY-----\n"\
"MIIEowIBAAKCAQEAy8Dbv8prpJ/0kKhlGeJYozo2t60EG8L0561g13R29LvMR5hy\n"\
"vGZlGJpmn65+A4xHXInJYiPuKzrKUnApeLZ+vw1HocOAZtWK0z3r26uA8kQYOKX9\n"\
"Qt/DbCdvsF9wF8gRK0ptx9M6R13NvBxvVQApfc9jB9nTzphOgM4JiEYvlV8FLhg9\n"\
"yZovMYd6Wwf3aoXK891VQxTr/kQYoq1Yp+68i6T4nNq7NWC+UNVjQHxNQMQMzU6l\n"\
"WCX8zyg3yH88OAQkUXIXKfQ+NkvYQ1cxaMoVPpY72+eVthKzpMeyHkBn7ciumk5q\n"\
"gLTEJAfWZpe4f4eFZj/Rc8Y8Jj2IS5kVPjUywQIDAQABAoIBADhg1u1Mv1hAAlX8\n"\
"omz1Gn2f4AAW2aos2cM5UDCNw1SYmj+9SRIkaxjRsE/C4o9sw1oxrg1/z6kajV0e\n"\
"N/t008FdlVKHXAIYWF93JMoVvIpMmT8jft6AN/y3NMpivgt2inmmEJZYNioFJKZG\n"\
"X+/vKYvsVISZm2fw8NfnKvAQK55yu+GRWBZGOeS9K+LbYvOwcrjKhHz66m4bedKd\n"\
"gVAix6NE5iwmjNXktSQlJMCjbtdNXg/xo1/G4kG2p/MO1HLcKfe1N5FgBiXj3Qjl\n"\
"vgvjJZkh1as2KTgaPOBqZaP03738VnYg23ISyvfT/teArVGtxrmFP7939EvJFKpF\n"\
"1wTxuDkCgYEA7t0DR37zt+dEJy+5vm7zSmN97VenwQJFWMiulkHGa0yU3lLasxxu\n"\
"m0oUtndIjenIvSx6t3Y+agK2F3EPbb0AZ5wZ1p1IXs4vktgeQwSSBdqcM8LZFDvZ\n"\
"uPboQnJoRdIkd62XnP5ekIEIBAfOp8v2wFpSfE7nNH2u4CpAXNSF9HsCgYEA2l8D\n"\
"JrDE5m9Kkn+J4l+AdGfeBL1igPF3DnuPoV67BpgiaAgI4h25UJzXiDKKoa706S0D\n"\
"4XB74zOLX11MaGPMIdhlG+SgeQfNoC5lE4ZWXNyESJH1SVgRGT9nBC2vtL6bxCVV\n"\
"WBkTeC5D6c/QXcai6yw6OYyNNdp0uznKURe1xvMCgYBVYYcEjWqMuAvyferFGV+5\n"\
"nWqr5gM+yJMFM2bEqupD/HHSLoeiMm2O8KIKvwSeRYzNohKTdZ7FwgZYxr8fGMoG\n"\
"PxQ1VK9DxCvZL4tRpVaU5Rmknud9hg9DQG6xIbgIDR+f79sb8QjYWmcFGc1SyWOA\n"\
"SkjlykZ2yt4xnqi3BfiD9QKBgGqLgRYXmXp1QoVIBRaWUi55nzHg1XbkWZqPXvz1\n"\
"I3uMLv1jLjJlHk3euKqTPmC05HoApKwSHeA0/gOBmg404xyAYJTDcCidTg6hlF96\n"\
"ZBja3xApZuxqM62F6dV4FQqzFX0WWhWp5n301N33r0qR6FumMKJzmVJ1TA8tmzEF\n"\
"yINRAoGBAJqioYs8rK6eXzA8ywYLjqTLu/yQSLBn/4ta36K8DyCoLNlNxSuox+A5\n"\
"w6z2vEfRVQDq4Hm4vBzjdi3QfYLNkTiTqLcvgWZ+eX44ogXtdTDO7c+GeMKWz4XX\n"\
"uJSUVL5+CVjKLjZEJ6Qc2WZLl94xSwL71E41H4YciVnSCQxVc4Jw\n"\
"-----END RSA PRIVATE KEY-----\n\0";

char publicKey[] ="-----BEGIN PUBLIC KEY-----\n"\
"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAy8Dbv8prpJ/0kKhlGeJY\n"\
"ozo2t60EG8L0561g13R29LvMR5hyvGZlGJpmn65+A4xHXInJYiPuKzrKUnApeLZ+\n"\
"vw1HocOAZtWK0z3r26uA8kQYOKX9Qt/DbCdvsF9wF8gRK0ptx9M6R13NvBxvVQAp\n"\
"fc9jB9nTzphOgM4JiEYvlV8FLhg9yZovMYd6Wwf3aoXK891VQxTr/kQYoq1Yp+68\n"\
"i6T4nNq7NWC+UNVjQHxNQMQMzU6lWCX8zyg3yH88OAQkUXIXKfQ+NkvYQ1cxaMoV\n"\
"PpY72+eVthKzpMeyHkBn7ciumk5qgLTEJAfWZpe4f4eFZj/Rc8Y8Jj2IS5kVPjUy\n"\
"wQIDAQAB\n"\
"-----END PUBLIC KEY-----\n";
  
  char* signature = signMessage(privateKey, plainText, len);
  //clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &start);
  int auth;
  for(int i = 0; i < 5; ++i) {
  	auth = verifySignature(publicKey, plainText, signature, len);
  }
  //clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &end);
  //long tt = (end.tv_nsec - start.tv_nsec) / 1000;
  //printf("time usage:%ld\n", tt);
  auth = auth ^ 0;

  long tt = 0;
  while(tt < time_verify_pir) {
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &start);
    uint64_t a = 100, b = 1000, c = 10000;
    uint64_t mod = ((uint64_t)1<<31)-1;
    for(int i = 0; i < (1<<12); ++i) {
      uint64_t d = a * b * c;
      a = (d * b) % mod;
      c = (a * d) % mod;
      b = (d * c) % mod;
    }
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &end);
    tt += (end.tv_nsec - start.tv_nsec) / 1000;
  }
  //printf("time usage:%ld\n", tt);
}
