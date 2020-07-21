#ifndef SHARED_H_
#define SHARED_H_

#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#ifdef _WIN32
#include <openssl/applink.c>
#endif
#include <openssl/rand.h>
#include <strings.h>
#include "define.h"
#include "omp.h"

int totalRandom = 0;
int totalSha = 0;
int totalSS = 0;
int totalHash = 0;

// int NUM_ROUNDS = 1;
int Nb = 4;
int Nk = 4;
int Nr = 10;

// uint32_t RANDOMNESS_LEN = (11648 * 8 * 2);
uint32_t RANDOMNESS_LEN = 119552;
// 102080

typedef struct {
  unsigned char x[512];
  uint32_t y[ySize];
} View;

// typedef struct {
// 	uint32_t yp[3][8];
// 	unsigned char h[3][32];
// } a;

typedef struct {
  uint8_t yp[3][OUTPUT_LEN];
  unsigned char h[3][32];
} a;

typedef struct {
  unsigned char ke[16];
  unsigned char ke1[16];
  View ve;
  View ve1;
  unsigned char re[4];
  unsigned char re1[4];
} z;

uint32_t rand32() {
  uint32_t x;
  x = rand() & 0xff;
  x |= (rand() & 0xff) << 8;
  x |= (rand() & 0xff) << 16;
  x |= (rand() & 0xff) << 24;

  return x;
}

void clear_array(uint8_t i, uint8_t j, uint8_t a[i][j]) {
  for (int m = 0; m < i; m++) {
    bzero(a[m], j);
  }
}

void free_array(uint8_t no, uint8_t* a[no]) {
  for (int i = 0; i < no; i++) {
    free(a[i]);
  }
}

void print_hex(unsigned char* var, unsigned long long len) {
  int i;
  for (i = 0; i < len; ++i) {
    printf("%02x", var[i]);
  }
  printf("\n");
}

void print_hex_info(unsigned char* var, unsigned long long len, char* info) {
  int i;
  printf("%s:", info);
  for (i = 0; i < len; ++i) {
    printf("%02x", var[i]);
  }
  printf("\n");
}

void check_state(unsigned char* name, uint8_t in[][3], int len) {
  uint8_t buf[len];
  bzero(buf, len);
  for (int i = 0; i < len; i++) {
    buf[i] = in[i][0] ^ in[i][1] ^ in[i][2];
  }

  printf("%s ", name);
  for (int i = 0; i < len; ++i) {
    printf("%02x", buf[i]);
  }
  printf("\n");
}

void check_state2(unsigned char* name, uint8_t in[][2], int len) {
  uint8_t buf[len];
  bzero(buf, len);
  for (int i = 0; i < len; i++) {
    buf[i] = in[i][0] ^ in[i][1];
  }

  printf("%s ", name);
  for (int i = 0; i < len; ++i) {
    printf("%02x", buf[i]);
  }
  printf("\n");
}

void handleErrors(void) {
  ERR_print_errors_fp(stderr);
  abort();
}

void setupAES(EVP_CIPHER_CTX* ctx, unsigned char key[16]) {
  EVP_CIPHER_CTX_init(ctx);

  /* A 128 bit IV */
  unsigned char* iv = (unsigned char*)"01234567890123456";

  if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, key, iv)) {
    EVP_CIPHER_CTX_free(ctx);
    handleErrors();
  }
}

void init_EVP() {
  // ERR_load_crypto_strings();
  // OpenSSL_add_all_algorithms();
  // OPENSSL_config(NULL);
  OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_CIPHERS |
                          OPENSSL_INIT_ADD_ALL_DIGESTS |
                          OPENSSL_INIT_LOAD_CRYPTO_STRINGS,
                      NULL);
}

void cleanup_EVP() {
  // CONF_modules_free();
  // CONF_modules_unload(1);
  CRYPTO_cleanup_all_ex_data();
  // ERR_free_strings();
  // ERR_remove_state(0);
  EVP_cleanup();
}

void get_all_randomness(unsigned char key[16],
                        unsigned char randomness[RANDOMNESS_LEN]) {
  // Generate randomness: We use 728*32 bit of randomness per key.
  // Since AES block size is 128 bit, we need to run 728*32/128 = 182 iterations

  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
  setupAES(ctx, key);
  unsigned char* plaintext = (unsigned char*)"0000000000000000";
  int len;
  for (int j = 0; j < (RANDOMNESS_LEN / 16); j++) {
    if (1 != EVP_EncryptUpdate(ctx, &randomness[j * 16], &len, plaintext,
                               strlen((char*)plaintext)))
      handleErrors();
  }
  EVP_CIPHER_CTX_cleanup(ctx);
}

void H(unsigned char k[16], View v, unsigned char r[4],
       unsigned char hash[SHA256_DIGEST_LENGTH]) {
  SHA256_CTX ctx;
  SHA256_Init(&ctx);
  SHA256_Update(&ctx, k, 16);
  SHA256_Update(&ctx, &v, sizeof(v));
  SHA256_Update(&ctx, r, 4);
  SHA256_Final(hash, &ctx);
}

void H3(uint8_t y[32], a* as, int s, int* es) {
  unsigned char hash[SHA256_DIGEST_LENGTH];
  memset(hash, 0, SHA256_DIGEST_LENGTH);
  SHA256_CTX ctx;
  SHA256_Init(&ctx);
  SHA256_Update(&ctx, y, 32);
  SHA256_Update(&ctx, as, sizeof(a) * s);
  SHA256_Final(hash, &ctx);

  // Pick bits from hash
  int i = 0;
  int bitTracker = 0;
  int b1 = 0;
  int b2 = 0;
  while (i < s) {
    if (bitTracker >=
        SHA256_DIGEST_LENGTH * 8) {  // Generate new hash as we have run out of
                                     // bits in the previous hash
      SHA256_Init(&ctx);
      SHA256_Update(&ctx, hash, sizeof(hash));
      SHA256_Final(hash, &ctx);
      bitTracker = 0;
    }

    b1 = GETBIT(hash[bitTracker / 8], bitTracker % 8);
    b2 = GETBIT(hash[(bitTracker + 1) / 8], (bitTracker + 1) % 8);
    if (b1 == 0) {
      if (b2 == 0) {
        es[i] = 0;
        bitTracker += 2;
        i++;
      } else {
        es[i] = 1;
        bitTracker += 2;
        i++;
      }
    } else {
      if (b2 == 0) {
        es[i] = 2;
        bitTracker += 2;
        i++;
      } else {
        bitTracker += 2;
      }
    }
  }
}

void output_var(View v, uint8_t* result, int len) {
  memcpy(result, &v.y[ySize - len / 4], len);
}

void output(View v, uint32_t* result) { memcpy(result, &v.y[ySize - 8], 32); }

void output_hmac(View v, uint32_t* result) {
  memcpy(result, &v.y[ySize - 8], 32);
}

void output_aes(View v, uint8_t* result) {
  memcpy(result, &v.y[ySize - 32 / 4], 32);
}

void reconstruct(uint8_t* y0, uint8_t* y1, uint8_t* y2, uint8_t* result) {
  for (int i = 0; i < OUTPUT_LEN; i++) {
    result[i] = y0[i] ^ y1[i] ^ y2[i];
  }
}

omp_lock_t* locks;

void openmp_locking_callback(int mode, int type, char* file, int line) {
  if (mode & CRYPTO_LOCK) {
    omp_set_lock(&locks[type]);
  } else {
    omp_unset_lock(&locks[type]);
  }
}

unsigned long openmp_thread_id(void) {
  return (unsigned long)omp_get_thread_num();
}

void openmp_thread_setup(void) {
  int i;

  locks = OPENSSL_malloc(CRYPTO_num_locks() * sizeof(omp_lock_t));
  for (i = 0; i < CRYPTO_num_locks(); i++) {
    omp_init_lock(&locks[i]);
  }

  CRYPTO_set_id_callback((unsigned long (*)())openmp_thread_id);
  CRYPTO_set_locking_callback((void (*)())openmp_locking_callback);
}

void openmp_thread_cleanup(void) {
  int i;

  CRYPTO_set_id_callback(NULL);
  CRYPTO_set_locking_callback(NULL);
  for (i = 0; i < CRYPTO_num_locks(); i++) omp_destroy_lock(&locks[i]);
  OPENSSL_free(locks);
}

#endif