#ifndef ZKLIIB_H_
#define ZKLIIB_H_

#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#ifdef _WIN32
#include <openssl/applink.c>
#endif
#include <openssl/rand.h>
#include <strings.h>
#include <unistd.h>
#include "define.h"
#include "omp.h"
#include "shared.h"

uint32_t getRandom32(unsigned char randomness[RANDOMNESS_LEN], int randCount) {
  uint32_t ret;
  memcpy(&ret, &randomness[randCount], 4);
  return ret;
}

uint8_t getRandom8(unsigned char randomness[RANDOMNESS_LEN], int randCount) {
  uint8_t ret;
  memcpy(&ret, &randomness[randCount], 1);
  return ret;
}

void mpc_XOR(uint32_t x[3], uint32_t y[3], uint32_t z[3]) {
  z[0] = x[0] ^ y[0];
  z[1] = x[1] ^ y[1];
  z[2] = x[2] ^ y[2];
}

void mpc_XOR_u8(uint8_t x[3], uint8_t y[3], uint8_t z[3]) {
  z[0] = x[0] ^ y[0];
  z[1] = x[1] ^ y[1];
  z[2] = x[2] ^ y[2];
}

void mpc_AND(uint32_t x[3], uint32_t y[3], uint32_t z[3],
             unsigned char* randomness[3], int* randCount, View views[3],
             int* countY) {
  clock_t t_begin = clock();

  uint32_t r[3] = {getRandom32(randomness[0], *randCount),
                   getRandom32(randomness[1], *randCount),
                   getRandom32(randomness[2], *randCount)};
  *randCount += 4;

  uint32_t t[3] = {0};

  t[0] = (x[0] & y[1]) ^ (x[1] & y[0]) ^ (x[0] & y[0]) ^ r[0] ^ r[1];
  t[1] = (x[1] & y[2]) ^ (x[2] & y[1]) ^ (x[1] & y[1]) ^ r[1] ^ r[2];
  t[2] = (x[2] & y[0]) ^ (x[0] & y[2]) ^ (x[2] & y[2]) ^ r[2] ^ r[0];
  z[0] = t[0];
  z[1] = t[1];
  z[2] = t[2];
  views[0].y[*countY] = z[0];
  views[1].y[*countY] = z[1];
  views[2].y[*countY] = z[2];
  (*countY)++;
}

void mpc_AND_u8(uint8_t x[3], uint8_t y[3], uint8_t z[3],
                unsigned char* randomness[3], int* randCount, View views[3],
                int* countY) {
  uint8_t r[3] = {getRandom8(randomness[0], *randCount),
                  getRandom8(randomness[1], *randCount),
                  getRandom8(randomness[2], *randCount)};
  *randCount += 1;
  uint8_t t[3] = {0, 0, 0};

  t[0] = (x[0] & y[1]) ^ (x[1] & y[0]) ^ (x[0] & y[0]) ^ r[0] ^ r[1];
  t[1] = (x[1] & y[2]) ^ (x[2] & y[1]) ^ (x[1] & y[1]) ^ r[1] ^ r[2];
  t[2] = (x[2] & y[0]) ^ (x[0] & y[2]) ^ (x[2] & y[2]) ^ r[2] ^ r[0];
  z[0] = t[0];
  z[1] = t[1];
  z[2] = t[2];

  views[0].y[*countY] = z[0];
  views[1].y[*countY] = z[1];
  views[2].y[*countY] = z[2];
  (*countY)++;
}

void mpc_ANDK_u8(uint8_t x[3], uint8_t y, uint8_t z[3],
                 unsigned char* randomness[3], int* randCount, View views[3],
                 int* countY) {
  uint8_t r[3] = {getRandom8(randomness[0], *randCount),
                  getRandom8(randomness[1], *randCount),
                  getRandom8(randomness[2], *randCount)};
  *randCount += 1;
  uint8_t t[3] = {0, 0, 0};

  // printf("%d, %d, %d, %d, %d\n", *randCount, *countY, r[0], r[1], r[2]);
  t[0] = (x[0] & y) ^ (x[1] & y) ^ (x[0] & y) ^ r[0] ^ r[1];
  t[1] = (x[1] & y) ^ (x[2] & y) ^ (x[1] & y) ^ r[1] ^ r[2];
  t[2] = (x[2] & y) ^ (x[0] & y) ^ (x[2] & y) ^ r[2] ^ r[0];

  z[0] = t[0];
  z[1] = t[1];
  z[2] = t[2];

  views[0].y[*countY] = z[0];
  views[1].y[*countY] = z[1];
  views[2].y[*countY] = z[2];

  // if (*countY == 6896) {
  // 	printf("debug\n");
  // 	printf("%d, %d\n", t[0] ^ t[1] ^ t[2],  (x[0] & y) ^ (x[1] & y) ^ (x[2]
  // & y)); 	printf("%d, %d, %d, %d, %d, %d, %d\n", x[0], x[1],x[2], y, r[0],
  // r[1], r[2]); 	printf("%d, %d, %d, %d\n", *countY, views[0].y[*countY],
  // *randCount,r[0]); 	printf("%d, %d, %d, %d\n", *countY, views[1].y[*countY],
  // *randCount,r[1]); 	printf("%d, %d, %d, %d\n", *countY,
  // views[2].y[*countY],*randCount,  r[2]);

  // 	printf("%d\n", (x[0] & y) ^ (x[1] & y) ^ (x[0] & y) ^ r[0] ^ r[1] );
  // 	for (int i=0; i < 8; i++){
  // 		printf("%d",  GETBIT(views[0].y[*countY], i));
  // 	}
  // 	printf("\n");
  // 	for (int i=0; i < 8; i++){
  // 		printf("%d",  GETBIT(z[0], i));
  // 	}
  // 	printf("\n");

  // 	for (int i=0; i < 8; i++){
  // 		printf("%d",  GETBIT(views[1].y[*countY], i));
  // 	}
  // 	printf("\n");
  // 	for (int i=0; i < 8; i++){
  // 		printf("%d",  GETBIT(z[1], i));
  // 	}
  // 	printf("\n");

  // 	for (int i=0; i < 8; i++){
  // 		printf("%d",  GETBIT(views[2].y[*countY], i));
  // 	}
  // 	printf("\n");
  // 	for (int i=0; i < 8; i++){
  // 		printf("%d",  GETBIT(z[2], i));
  // 	}
  // 	printf("\n");

  // }

  (*countY)++;
}

int mpc_ANDK_verify_u8(uint8_t x[2], uint8_t y, uint8_t z[2], View* ve,
                       View* ve1, unsigned char* randomness[2], int* randCount,
                       int* countY) {
  uint8_t r[2] = {getRandom8(randomness[0], *randCount),
                  getRandom8(randomness[1], *randCount)};
  *randCount += 1;

  // printf("%d, %d, %d, %d\n", *randCount, *countY, r[0], r[1]);
  uint8_t t = 0;
  uint8_t t1 = 0;

  t = (x[0] & y) ^ (x[1] & y) ^ (x[0] & y) ^ r[0] ^ r[1];
  t1 = (x[1] & y) ^ (x[0] & y) ^ (x[1] & y) ^ r[0] ^ r[1];

  if (ve->y[*countY] != t) {
    // printf("%d, %d, %d, %d, %d\n", x[0], x[1], y, r[0], r[1]);
    // printf("%d, %d, %d, %d, %d\n", *countY, ve->y[*countY], t, *randCount, t1
    // ); printf("%d, %d, %d, %d, %d\n", *countY, ve1->y[*countY], t,
    // *randCount, t1 ); for (int i=0; i < 8; i++){ 	printf("%d",  GETBIT(t, i));
    // }
    // printf("\n");
    // for (int i=0; i < 8; i++){
    // 	printf("%d",  GETBIT(t1, i));
    // }
    // printf("\n");

    // for (int i=0; i < 8; i++){
    // 	printf("%d",  GETBIT(ve->y[*countY], i));
    // }
    // printf("\n");

    // (*countY)++;
    return FAIL;
  }
  z[0] = t;
  z[1] = ve1->y[*countY];

  (*countY)++;
  return PASS;
}

int mpc_AND_verify(uint32_t x[2], uint32_t y[2], uint32_t z[2], View* ve,
                   View* ve1, unsigned char* randomness[2], int* randCount,
                   int* countY) {
  uint32_t r[2] = {getRandom32(randomness[0], *randCount),
                   getRandom32(randomness[1], *randCount)};
  *randCount += 4;

  uint32_t t = 0;

  t = (x[0] & y[1]) ^ (x[1] & y[0]) ^ (x[0] & y[0]) ^ r[0] ^ r[1];
  if (ve->y[*countY] != t) {
    (*countY)++;
    return FAIL;
  }
  z[0] = t;
  z[1] = ve1->y[*countY];
  (*countY)++;
  return PASS;
}

int mpc_AND_verify_u8(uint8_t x[2], uint8_t y[2], uint8_t z[2], View* ve,
                      View* ve1, unsigned char* randomness[2], int* randCount,
                      int* countY) {
  uint8_t r[2] = {getRandom8(randomness[0], *randCount),
                  getRandom8(randomness[1], *randCount)};
  *randCount += 1;

  uint8_t t = 0;

  t = (x[0] & y[1]) ^ (x[1] & y[0]) ^ (x[0] & y[0]) ^ r[0] ^ r[1];
  if (ve->y[*countY] != t) {
    // (*countY)++;

    return FAIL;
  }
  z[0] = t;
  z[1] = ve1->y[*countY];

  (*countY)++;
  return PASS;
}

void mpc_XNOR_u8(uint8_t x[3], uint8_t y[3], uint8_t z[3]) {
  z[0] = 1 ^ (x[0] ^ y[0]);
  z[1] = 1 ^ (x[1] ^ y[1]);
  z[2] = 1 ^ (x[2] ^ y[2]);
}

void mpc_XNOR2_u8(uint8_t x[2], uint8_t y[2], uint8_t z[2]) {
  z[0] = 1 ^ (x[0] ^ y[0]);
  z[1] = 1 ^ (x[1] ^ y[1]);
}

void mpc_NEGATE(uint32_t x[3], uint32_t z[3]) {
  z[0] = ~x[0];
  z[1] = ~x[1];
  z[2] = ~x[2];
}

void mpc_NEGATE_u8(uint8_t x[3], uint8_t z[3]) {
  z[0] = ~x[0];
  z[1] = ~x[1];
  z[2] = ~x[2];
}

void mpc_OR_u8(uint8_t x[3], uint8_t y[3], uint8_t z[3],
               unsigned char* randomness[3], int* randCount, View views[3],
               int* countY) {
  uint8_t t0[3];
  uint8_t t1[3];
  mpc_AND_u8(x, x, t0, randomness, randCount, views, countY);
  mpc_NEGATE_u8(t0, t0);
  mpc_AND_u8(y, y, t1, randomness, randCount, views, countY);
  mpc_NEGATE_u8(t1, t1);
  mpc_AND_u8(t0, t1, z, randomness, randCount, views, countY);
  mpc_NEGATE_u8(z, z);
}

void mpc_RIGHTROTATE(uint32_t x[], int i, uint32_t z[]) {
  z[0] = RIGHTROTATE(x[0], i);
  z[1] = RIGHTROTATE(x[1], i);
  z[2] = RIGHTROTATE(x[2], i);
}

void mpc_RIGHTSHIFT(uint32_t x[3], int i, uint32_t z[3]) {
  z[0] = x[0] >> i;
  z[1] = x[1] >> i;
  z[2] = x[2] >> i;
}

void mpc_RIGHTSHIFT_u8(uint8_t x[3], int i, uint8_t z[3]) {
  z[0] = x[0] >> i;
  z[1] = x[1] >> i;
  z[2] = x[2] >> i;
}

void mpc_LEFTSHIFT_u8(uint8_t x[3], int i, uint8_t z[3]) {
  z[0] = x[0] << i;
  z[1] = x[1] << i;
  z[2] = x[2] << i;
}

void mpc_MAJ(uint32_t a[], uint32_t b[3], uint32_t c[3], uint32_t z[3],
             unsigned char* randomness[3], int* randCount, View views[3],
             int* countY) {
  uint32_t t0[3];
  uint32_t t1[3];

  mpc_XOR(a, b, t0);
  mpc_XOR(a, c, t1);
  mpc_AND(t0, t1, z, randomness, randCount, views, countY);
  mpc_XOR(z, a, z);
}

void mpc_CH(uint32_t e[], uint32_t f[3], uint32_t g[3], uint32_t z[3],
            unsigned char* randomness[3], int* randCount, View views[3],
            int* countY) {
  uint32_t t0[3];

  // e & (f^g) ^ g
  mpc_XOR(f, g, t0);
  mpc_AND(e, t0, t0, randomness, randCount, views, countY);
  mpc_XOR(t0, g, z);
}

void mpc_XOR2(uint32_t x[2], uint32_t y[2], uint32_t z[2]) {
  z[0] = x[0] ^ y[0];
  z[1] = x[1] ^ y[1];
}

void mpc_NEGATE2(uint32_t x[2], uint32_t z[2]) {
  z[0] = ~x[0];
  z[1] = ~x[1];
}

void mpc_RIGHTROTATE2(uint32_t x[], int i, uint32_t z[]) {
  z[0] = RIGHTROTATE(x[0], i);
  z[1] = RIGHTROTATE(x[1], i);
}

void mpc_RIGHTSHIFT2(uint32_t x[2], int i, uint32_t z[2]) {
  z[0] = x[0] >> i;
  z[1] = x[1] >> i;
}

void mpc_XOR2_u8(uint8_t x[2], uint8_t y[2], uint8_t z[2]) {
  z[0] = x[0] ^ y[0];
  z[1] = x[1] ^ y[1];
}

void mpc_NEGATE2_u8(uint8_t x[2], uint8_t z[2]) {
  z[0] = ~x[0];
  z[1] = ~x[1];
}

void mpc_RIGHTROTATE2_u8(uint8_t x[], int i, uint8_t z[]) {
  z[0] = RIGHTROTATE(x[0], i);
  z[1] = RIGHTROTATE(x[1], i);
}

void mpc_RIGHTSHIFT2_u8(uint8_t x[2], int i, uint8_t z[2]) {
  z[0] = x[0] >> i;
  z[1] = x[1] >> i;
}

void mpc_LEFTSHIFT2_u8(uint8_t x[2], int i, uint8_t z[2]) {
  z[0] = x[0] << i;
  z[1] = x[1] << i;
}

void mpc_ADD(uint32_t x[3], uint32_t y[3], uint32_t z[3],
             unsigned char* randomness[3], int* randCount, View views[3],
             int* countY) {
  uint32_t c[3] = {0};
  uint32_t r[3] = {getRandom32(randomness[0], *randCount),
                   getRandom32(randomness[1], *randCount),
                   getRandom32(randomness[2], *randCount)};
  *randCount += 4;
  // printf("mpc_ADD: %d, %d, %d, %d, %d, ", *randCount, r[0], r[1], r[2],
  // *countY);

  uint8_t a[3], b[3];

  uint8_t t;

  for (int i = 0; i < 31; i++) {
    a[0] = GETBIT(x[0] ^ c[0], i);
    a[1] = GETBIT(x[1] ^ c[1], i);
    a[2] = GETBIT(x[2] ^ c[2], i);

    b[0] = GETBIT(y[0] ^ c[0], i);
    b[1] = GETBIT(y[1] ^ c[1], i);
    b[2] = GETBIT(y[2] ^ c[2], i);

    t = (a[0] & b[1]) ^ (a[1] & b[0]) ^ GETBIT(r[1], i);
    SETBIT(c[0], i + 1, t ^ (a[0] & b[0]) ^ GETBIT(c[0], i) ^ GETBIT(r[0], i));

    t = (a[1] & b[2]) ^ (a[2] & b[1]) ^ GETBIT(r[2], i);
    SETBIT(c[1], i + 1, t ^ (a[1] & b[1]) ^ GETBIT(c[1], i) ^ GETBIT(r[1], i));

    t = (a[2] & b[0]) ^ (a[0] & b[2]) ^ GETBIT(r[0], i);
    SETBIT(c[2], i + 1, t ^ (a[2] & b[2]) ^ GETBIT(c[2], i) ^ GETBIT(r[2], i));
  }

  // printf("%d, %d, %d\n", y[0], y[1], y[2]);
  z[0] = x[0] ^ y[0] ^ c[0];
  z[1] = x[1] ^ y[1] ^ c[1];
  z[2] = x[2] ^ y[2] ^ c[2];

  views[0].y[*countY] = c[0];
  views[1].y[*countY] = c[1];
  views[2].y[*countY] = c[2];

  *countY += 1;
}

void mpc_ADD_u8(uint8_t x[3], uint8_t y[3], uint8_t z[3],
                unsigned char* randomness[3], int* randCount, View views[3],
                int* countY) {
  uint8_t c[3] = {0};
  uint8_t r[3] = {getRandom8(randomness[0], *randCount),
                  getRandom8(randomness[1], *randCount),
                  getRandom8(randomness[2], *randCount)};
  *randCount += 1;
  // printf("%d, %d, %d\n", r[0], r[1], r[2]);
  uint8_t a[3], b[3];

  uint8_t t;

  for (int i = 0; i < 7; i++) {
    a[0] = GETBIT(x[0] ^ c[0], i);
    a[1] = GETBIT(x[1] ^ c[1], i);
    a[2] = GETBIT(x[2] ^ c[2], i);

    b[0] = GETBIT(y[0] ^ c[0], i);
    b[1] = GETBIT(y[1] ^ c[1], i);
    b[2] = GETBIT(y[2] ^ c[2], i);

    t = (a[0] & b[1]) ^ (a[1] & b[0]) ^ GETBIT(r[1], i);
    SETBIT(c[0], i + 1, t ^ (a[0] & b[0]) ^ GETBIT(c[0], i) ^ GETBIT(r[0], i));

    t = (a[1] & b[2]) ^ (a[2] & b[1]) ^ GETBIT(r[2], i);
    SETBIT(c[1], i + 1, t ^ (a[1] & b[1]) ^ GETBIT(c[1], i) ^ GETBIT(r[1], i));

    t = (a[2] & b[0]) ^ (a[0] & b[2]) ^ GETBIT(r[0], i);
    SETBIT(c[2], i + 1, t ^ (a[2] & b[2]) ^ GETBIT(c[2], i) ^ GETBIT(r[2], i));
  }

  z[0] = x[0] ^ y[0] ^ c[0];
  z[1] = x[1] ^ y[1] ^ c[1];
  z[2] = x[2] ^ y[2] ^ c[2];

  views[0].y[*countY] = c[0];
  views[1].y[*countY] = c[1];
  views[2].y[*countY] = c[2];

  *countY += 1;
}

void mpc_ADDK(uint32_t x[3], uint32_t y, uint32_t z[3],
              unsigned char* randomness[3], int* randCount, View views[3],
              int* countY) {
  uint32_t c[3] = {0};
  uint32_t r[3] = {getRandom32(randomness[0], *randCount),
                   getRandom32(randomness[1], *randCount),
                   getRandom32(randomness[2], *randCount)};
  *randCount += 4;

  uint8_t a[3], b[3];

  uint8_t t;

  for (int i = 0; i < 31; i++) {
    a[0] = GETBIT(x[0] ^ c[0], i);
    a[1] = GETBIT(x[1] ^ c[1], i);
    a[2] = GETBIT(x[2] ^ c[2], i);

    b[0] = GETBIT(y ^ c[0], i);
    b[1] = GETBIT(y ^ c[1], i);
    b[2] = GETBIT(y ^ c[2], i);

    t = (a[0] & b[1]) ^ (a[1] & b[0]) ^ GETBIT(r[1], i);
    SETBIT(c[0], i + 1, t ^ (a[0] & b[0]) ^ GETBIT(c[0], i) ^ GETBIT(r[0], i));

    t = (a[1] & b[2]) ^ (a[2] & b[1]) ^ GETBIT(r[2], i);
    SETBIT(c[1], i + 1, t ^ (a[1] & b[1]) ^ GETBIT(c[1], i) ^ GETBIT(r[1], i));

    t = (a[2] & b[0]) ^ (a[0] & b[2]) ^ GETBIT(r[0], i);
    SETBIT(c[2], i + 1, t ^ (a[2] & b[2]) ^ GETBIT(c[2], i) ^ GETBIT(r[2], i));
  }

  z[0] = x[0] ^ y ^ c[0];
  z[1] = x[1] ^ y ^ c[1];
  z[2] = x[2] ^ y ^ c[2];

  views[0].y[*countY] = c[0];
  views[1].y[*countY] = c[1];
  views[2].y[*countY] = c[2];
  *countY += 1;
}

int mpc_ADD_verify(uint32_t x[2], uint32_t y[2], uint32_t z[2], View* ve,
                   View* ve1, unsigned char* randomness[2], int* randCount,
                   int* countY) {
  // clock_t	t_begin = clock();
  uint32_t r[2] = {getRandom32(randomness[0], *randCount),
                   getRandom32(randomness[1], *randCount)};
  *randCount += 4;
  // printf("mpc_ADD verify: %d, %d, %d, %d, %d, %d\n", *randCount, r[0], r[1],
  // *countY, y[0], y[1]);
  uint8_t a[2], b[2];

  uint8_t t;

  for (int i = 0; i < 31; i++) {
    a[0] = GETBIT(x[0] ^ ve->y[*countY], i);
    a[1] = GETBIT(x[1] ^ ve1->y[*countY], i);

    b[0] = GETBIT(y[0] ^ ve->y[*countY], i);
    b[1] = GETBIT(y[1] ^ ve1->y[*countY], i);

    t = (a[0] & b[1]) ^ (a[1] & b[0]) ^ GETBIT(r[1], i);
    if (GETBIT(ve->y[*countY], i + 1) !=
        (t ^ (a[0] & b[0]) ^ GETBIT(ve->y[*countY], i) ^ GETBIT(r[0], i))) {
          printf("Fail: %d %d\n", GETBIT(ve->y[*countY], i + 1), i);
      // (*countY)++;
      // printf("sha256 add gate time (inner1) %ju us\n", (uintmax_t)(clock() -
      // t_begin) * 1000* 1000 / CLOCKS_PER_SEC);
      return FAIL;
    }
  }

  z[0] = x[0] ^ y[0] ^ ve->y[*countY];
  z[1] = x[1] ^ y[1] ^ ve1->y[*countY];
  (*countY)++;
  // printf("sha256 add gate time (inner2) %ju us\n", (uintmax_t)(clock() -
  // t_begin) * 1000* 1000 / CLOCKS_PER_SEC);
  return 0;
}

int mpc_ADD_verify_u8(uint8_t x[2], uint8_t y[2], uint8_t z[2], View* ve,
                      View* ve1, unsigned char* randomness[2], int* randCount,
                      int* countY) {
  uint8_t r[2] = {getRandom8(randomness[0], *randCount),
                  getRandom8(randomness[1], *randCount)};
  *randCount += 1;
  // printf("%d, %d\n", r[0], r[1]);
  uint8_t a[2], b[2];

  uint8_t t;

  for (int i = 0; i < 7; i++) {
    a[0] = GETBIT(x[0] ^ ve->y[*countY], i);
    a[1] = GETBIT(x[1] ^ ve1->y[*countY], i);

    b[0] = GETBIT(y[0] ^ ve->y[*countY], i);
    b[1] = GETBIT(y[1] ^ ve1->y[*countY], i);

    t = (a[0] & b[1]) ^ (a[1] & b[0]) ^ GETBIT(r[1], i);

    if (GETBIT(ve->y[*countY], i + 1) !=
        (t ^ (a[0] & b[0]) ^ GETBIT(ve->y[*countY], i) ^ GETBIT(r[0], i))) {
      // (*countY)++;
      return FAIL;
    }
  }

  z[0] = x[0] ^ y[0] ^ ve->y[*countY];
  z[1] = x[1] ^ y[1] ^ ve1->y[*countY];
  (*countY)++;
  return PASS;
}

int mpc_ADDK_verify(uint32_t x[2], uint32_t y, uint32_t z[2], View* ve,
                    View* ve1, unsigned char* randomness[2], int* randCount,
                    int* countY) {
  uint32_t r[2] = {getRandom32(randomness[0], *randCount),
                   getRandom32(randomness[1], *randCount)};
  *randCount += 4;

  uint8_t a[2], b[2];

  uint8_t t;

  for (int i = 0; i < 31; i++) {
    a[0] = GETBIT(x[0] ^ ve->y[*countY], i);
    a[1] = GETBIT(x[1] ^ ve1->y[*countY], i);

    b[0] = GETBIT(y ^ ve->y[*countY], i);
    b[1] = GETBIT(y ^ ve1->y[*countY], i);

    t = (a[0] & b[1]) ^ (a[1] & b[0]) ^ GETBIT(r[1], i);
    if (GETBIT(ve->y[*countY], i + 1) !=
        (t ^ (a[0] & b[0]) ^ GETBIT(ve->y[*countY], i) ^ GETBIT(r[0], i))) {
      // (*countY)++;
      return FAIL;
    }
  }

  z[0] = x[0] ^ y ^ ve->y[*countY];
  z[1] = x[1] ^ y ^ ve1->y[*countY];
  (*countY)++;
  return PASS;
}

int mpc_ADD_verify_test(uint32_t x[2], uint32_t y[2], uint32_t z[2], View* ve,
                        View* ve1, unsigned char* randomness[2], int* randCount,
                        int* countY) {
  clock_t t_begin = clock();
  uint32_t r[2] = {getRandom32(randomness[0], *randCount),
                   getRandom32(randomness[1], *randCount)};
  *randCount += 4;

  uint8_t a[2], b[2];

  uint8_t t;

  for (int i = 0; i < 31; i++) {
    a[0] = GETBIT(x[0] ^ ve->y[*countY], i);
    a[1] = GETBIT(x[1] ^ ve1->y[*countY], i);

    b[0] = GETBIT(y[0] ^ ve->y[*countY], i);
    b[1] = GETBIT(y[1] ^ ve1->y[*countY], i);

    t = (a[0] & b[1]) ^ (a[1] & b[0]) ^ GETBIT(r[1], i);
    if (GETBIT(ve->y[*countY], i + 1) ^
        (t ^ (a[0] & b[0]) ^ GETBIT(ve->y[*countY], i) ^ GETBIT(r[0], i))) {
      // (*countY)++;
      // printf("sha256 add gate time (inner1) %ju us\n", (uintmax_t)(clock() -
      // t_begin) * 1000* 1000 / CLOCKS_PER_SEC);
      return FAIL;
    }
  }

  z[0] = x[0] ^ y[0] ^ ve->y[*countY];
  z[1] = x[1] ^ y[1] ^ ve1->y[*countY];
  (*countY)++;
  // printf("sha256 add gate time (inner2) %ju us\n", (uintmax_t)(clock() -
  // t_begin) * 1000* 1000 / CLOCKS_PER_SEC);
  return 0;
}

int mpc_MAJ_verify(uint32_t a[2], uint32_t b[2], uint32_t c[2], uint32_t z[3],
                   View* ve, View* ve1, unsigned char* randomness[2],
                   int* randCount, int* countY) {
  uint32_t t0[2];
  uint32_t t1[2];

  mpc_XOR2(a, b, t0);
  mpc_XOR2(a, c, t1);
  if (mpc_AND_verify(t0, t1, z, ve, ve1, randomness, randCount, countY) == 1) {
#if VERFDEBUG
    mpc_XOR2(z, a, z);
#endif
    return FAIL;
  }
  mpc_XOR2(z, a, z);
  return PASS;
}

int mpc_MAJ_verify_u8(uint8_t a[2], uint8_t b[2], uint8_t c[2], uint8_t z[3],
                      View* ve, View* ve1, unsigned char* randomness[2],
                      int* randCount, int* countY) {
  uint8_t t0[2];
  uint8_t t1[2];

  mpc_XOR2_u8(a, b, t0);
  mpc_XOR2_u8(a, c, t1);
  if (mpc_AND_verify_u8(t0, t1, z, ve, ve1, randomness, randCount, countY) ==
      1) {
#if VERFDEBUG
    mpc_XOR2_u8(z, a, z);
#endif
    return FAIL;
  }
  mpc_XOR2_u8(z, a, z);
  return PASS;
}

int mpc_CH_verify(uint32_t e[2], uint32_t f[2], uint32_t g[2], uint32_t z[2],
                  View* ve, View* ve1, unsigned char* randomness[2],
                  int* randCount, int* countY) {
  uint32_t t0[2];
  mpc_XOR2(f, g, t0);
  if (mpc_AND_verify(e, t0, t0, ve, ve1, randomness, randCount, countY) == 1) {
#if VERFDEBUG
    mpc_XOR2(t0, g, z);
#endif
    return FAIL;
  }
  mpc_XOR2(t0, g, z);

  return PASS;
}

int mpc_CH_verify_u8(uint8_t e[2], uint8_t f[2], uint8_t g[2], uint8_t z[2],
                     View* ve, View* ve1, unsigned char* randomness[2],
                     int* randCount, int* countY) {
  uint8_t t0[2];
  mpc_XOR2_u8(f, g, t0);
  if (mpc_AND_verify_u8(e, t0, t0, ve, ve1, randomness, randCount, countY) ==
      1) {
#if VERFDEBUG
    mpc_XOR2_u8(t0, g, z);
#endif
    return FAIL;
  }
  mpc_XOR2_u8(t0, g, z);
  return PASS;
}

int mpc_OR_verify_u8(uint8_t x[2], uint8_t y[2], uint8_t z[2], View* ve,
                     View* ve1, unsigned char* randomness[2], int* randCount,
                     int* countY) {
  uint8_t t0[2];
  uint8_t t1[2];
  uint8_t a, b, c;
  a = mpc_AND_verify_u8(x, x, t0, ve, ve1, randomness, randCount, countY);
  mpc_NEGATE2_u8(t0, t0);
  b = mpc_AND_verify_u8(y, y, t1, ve, ve1, randomness, randCount, countY);
  mpc_NEGATE2_u8(t1, t1);
  c = mpc_AND_verify_u8(t0, t1, z, ve, ve1, randomness, randCount, countY);
  mpc_NEGATE2_u8(z, z);
  if (a | b | c) {
    return FAIL;
  }
  return PASS;
}

#endif