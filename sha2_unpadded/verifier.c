/*
 ============================================================================
 Name        : MPC_SHA256_VERIFIER.c
 Author      : Sobuno
 Version     : 0.1
 Description : Verifies a proof for SHA-256 generated by MPC_SHA256.c
 ============================================================================
 */

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "aes.h"
#include "shared.h"
#include "zklib.h"

int round_no;

void error_handler(int line, char* type) {
  // #if VERBOSE
  printf("Failed at %d, function %s\n", line, type);
  // return FAIL;
  exit(0);

  //#endif
}

void error_handler2(int line, char* type) {
  // #if VERBOSE
  printf("Failed at %d, function %s\n", line, type);
  // return FAIL;
  exit(0);

  //#endif
}

void error_handler1(int line) {
  // #if VERBOSE
  printf("Failed at %d, iteration %d\n", line, round_no);
  // return FAIL;
  exit(0);

  //#endif
}

/**
 * SHA-2 with two differences:
 *  1) Assumes padded input, fails otherwise
 *  2) State is taken as input
 */
int mpc_sha256_padded(unsigned char* results[2], unsigned char* inputs[2], z z, int numBits, unsigned char* randomness[2],
                      int* randCount, int* countY, int view_idx) {
  int inputBits = numBits - STATE_LEN * 8;
	int chars = inputBits >> 3;
  if (chars % 64 != 0) {
    printf("Input unpadded");
    exit(0);
  }
  int used_len = 0;
  unsigned char* chunks;
  uint32_t w[64][2];
  uint32_t a[2], b[2], c[2], d[2], e[2], f[2], g[2], h[2];
  uint32_t s0[2], s1[2];
  uint32_t t0[2], t1[2];

	uint32_t ctx[8][3];

  for (int j=0; j<8; j++) {
    for (int i=0; i<2; i++) {
      ctx[j][i] = (inputs[i][j * 4] << 24) | (inputs[i][j * 4 + 1] << 16) |
									(inputs[i][j * 4 + 2] << 8) | inputs[i][j * 4 + 3];
    }
  }

  View* pve = &z.ve;
  View* pve1 = &z.ve1;  

  int wi = 0;

  int block_no = chars / 64;
  bool setOne[2] = {false, false};

  for (int rd = 0; rd < block_no; rd++) {
    int blk = chars < 64 ? chars : 64;
    // pre-process input into chunks
    for (int i = 0; i < 2; i++) {
      chunks = calloc(64, sizeof(unsigned char));
      memcpy(chunks, inputs[i] + STATE_LEN + 64 * rd, blk);
      wi += blk;
      for (int j = 0; j < 16; j++) {
        w[j][i] = (chunks[j * 4] << 24) | (chunks[j * 4 + 1] << 16) |
                  (chunks[j * 4 + 2] << 8) | chunks[j * 4 + 3];
      }
      free(chunks);
    }

    for (int j = 16; j < 64; j++) {
      mpc_RIGHTROTATE2(w[j - 15], 7, t0);

      mpc_RIGHTROTATE2(w[j - 15], 18, t1);
      mpc_XOR2(t0, t1, t0);
      mpc_RIGHTSHIFT2(w[j - 15], 3, t1);
      mpc_XOR2(t0, t1, s0);

      mpc_RIGHTROTATE2(w[j - 2], 17, t0);
      mpc_RIGHTROTATE2(w[j - 2], 19, t1);

      mpc_XOR2(t0, t1, t0);
      mpc_RIGHTSHIFT2(w[j - 2], 10, t1);
      mpc_XOR2(t0, t1, s1);

      if (mpc_ADD_verify(w[j - 16], s0, t1, pve, pve1, randomness, randCount,
                         countY) == FAIL)
        error_handler2(__LINE__, "ADD");
      if (mpc_ADD_verify(w[j - 7], t1, t1, pve, pve1, randomness, randCount,
                         countY) == FAIL)
        error_handler2(__LINE__, "ADD");
      // clock_t	t_begin = clock();
      if (mpc_ADD_verify(t1, s1, w[j], pve, pve1, randomness, randCount,
                         countY) == FAIL)
        error_handler2(__LINE__, "ADD");
    }

    memcpy(a, ctx[0], sizeof(a));
    memcpy(b, ctx[1], sizeof(b));
    memcpy(c, ctx[2], sizeof(c));
    memcpy(d, ctx[3], sizeof(d));
    memcpy(e, ctx[4], sizeof(e));
    memcpy(f, ctx[5], sizeof(f));
    memcpy(g, ctx[6], sizeof(g));
    memcpy(h, ctx[7], sizeof(h));

    uint32_t temp1[2], temp2[2], maj[2];
    for (int i = 0; i < 64; i++) {
      // s1 = RIGHTROTATE(e,6) ^ RIGHTROTATE(e,11) ^ RIGHTROTATE(e,25);
      mpc_RIGHTROTATE2(e, 6, t0);
      mpc_RIGHTROTATE2(e, 11, t1);
      mpc_XOR2(t0, t1, t0);

      mpc_RIGHTROTATE2(e, 25, t1);
      mpc_XOR2(t0, t1, s1);

      if (mpc_ADD_verify(h, s1, t0, pve, pve1, randomness, randCount, countY) ==
          FAIL)
        error_handler2(__LINE__, "ADD");

      if (mpc_CH_verify(e, f, g, t1, pve, pve1, randomness, randCount,
                        countY) == FAIL)
        error_handler2(__LINE__, "CH");
      if (mpc_ADD_verify(t0, t1, t1, pve, pve1, randomness, randCount,
                         countY) == FAIL)
        error_handler2(__LINE__, "ADD");

      t0[0] = k[i];
      t0[1] = k[i];

      if (mpc_ADD_verify(t1, t0, t1, pve, pve1, randomness, randCount,
                         countY) == FAIL)
        error_handler2(__LINE__, "ADDK");

      if (mpc_ADD_verify(t1, w[i], temp1, pve, pve1, randomness, randCount,
                         countY) == FAIL)
        error_handler2(__LINE__, "ADD");

      mpc_RIGHTROTATE2(a, 2, t0);
      mpc_RIGHTROTATE2(a, 13, t1);
      mpc_XOR2(t0, t1, t0);
      mpc_RIGHTROTATE2(a, 22, t1);
      mpc_XOR2(t0, t1, s0);

      if (mpc_MAJ_verify(a, b, c, maj, pve, pve1, randomness, randCount,
                         countY) == FAIL)
        error_handler2(__LINE__, "MAJ");

      if (mpc_ADD_verify(s0, maj, temp2, pve, pve1, randomness, randCount,
                         countY) == FAIL)
        error_handler2(__LINE__, "ADD");

      memcpy(h, g, sizeof(uint32_t) * 2);
      memcpy(g, f, sizeof(uint32_t) * 2);
      memcpy(f, e, sizeof(uint32_t) * 2);

      if (mpc_ADD_verify(d, temp1, e, pve, pve1, randomness, randCount,
                         countY) == FAIL)
        error_handler2(__LINE__, "ADD");

      memcpy(d, c, sizeof(uint32_t) * 2);
      memcpy(c, b, sizeof(uint32_t) * 2);
      memcpy(b, a, sizeof(uint32_t) * 2);

      if (mpc_ADD_verify(temp1, temp2, a, pve, pve1, randomness, randCount,
                         countY) == FAIL)
        error_handler(__LINE__, "ADD");
      // exit(1);
    }

    if (mpc_ADD_verify(ctx[0], a, ctx[0], pve, pve1, randomness, randCount,
                       countY) == FAIL)
      error_handler2(__LINE__, "ADD");
    if (mpc_ADD_verify(ctx[1], b, ctx[1], pve, pve1, randomness, randCount,
                       countY) == FAIL)
      error_handler2(__LINE__, "ADD");
    if (mpc_ADD_verify(ctx[2], c, ctx[2], pve, pve1, randomness, randCount,
                       countY) == FAIL)
      error_handler2(__LINE__, "ADD");
    if (mpc_ADD_verify(ctx[3], d, ctx[3], pve, pve1, randomness, randCount,
                       countY) == FAIL)
      error_handler2(__LINE__, "ADD");
    if (mpc_ADD_verify(ctx[4], e, ctx[4], pve, pve1, randomness, randCount,
                       countY) == FAIL)
      error_handler2(__LINE__, "ADD");
    if (mpc_ADD_verify(ctx[5], f, ctx[5], pve, pve1, randomness, randCount,
                       countY) == FAIL)
      error_handler2(__LINE__, "ADD");
    if (mpc_ADD_verify(ctx[6], g, ctx[6], pve, pve1, randomness, randCount,
                       countY) == FAIL)
      error_handler2(__LINE__, "ADD");
    if (mpc_ADD_verify(ctx[7], h, ctx[7], pve, pve1, randomness, randCount,
                       countY) == FAIL)
      error_handler2(__LINE__, "ADD");

    chars -= blk;
  }

  for (int i = 0; i < 8; i++) {
    mpc_RIGHTSHIFT2(ctx[i], 24, t0);
    results[0][i * 4] = t0[0];
    results[1][i * 4] = t0[1];

    mpc_RIGHTSHIFT2(ctx[i], 16, t0);
    results[0][i * 4 + 1] = t0[0];
    results[1][i * 4 + 1] = t0[1];

    mpc_RIGHTSHIFT2(ctx[i], 8, t0);
    results[0][i * 4 + 2] = t0[0];
    results[1][i * 4 + 2] = t0[1];

    results[0][i * 4 + 3] = ctx[i][0];
    results[1][i * 4 + 3] = ctx[i][1];
  }

  return used_len;
}

int verify(a a, int e, z z) {
  unsigned char* hash = malloc(SHA256_DIGEST_LENGTH);
  H(z.ke, z.ve, z.re, hash);

  if (memcmp(a.h[e], hash, 32) != 0) error_handler1(__LINE__);

  H(z.ke1, z.ve1, z.re1, hash);
  if (memcmp(a.h[(e + 1) % 3], hash, 32) != 0) error_handler1(__LINE__);
  free(hash);

  uint8_t* result = malloc(OUTPUT_LEN);
  output_var(z.ve, result, OUTPUT_LEN);

  if (memcmp(a.yp[e], result, OUTPUT_LEN) != 0) error_handler1(__LINE__);

  output_var(z.ve1, result, OUTPUT_LEN);
  if (memcmp(a.yp[(e + 1) % 3], result, OUTPUT_LEN) != 0) error_handler1(__LINE__);

  free(result);

  int input_len = STATE_LEN + USER_INPUT_LEN;

  unsigned char* randomness[2];
  randomness[0] = calloc(RANDOMNESS_LEN, sizeof(unsigned char));
  randomness[1] = calloc(RANDOMNESS_LEN, sizeof(unsigned char));
  get_all_randomness(z.ke, randomness[0]);
  get_all_randomness(z.ke1, randomness[1]);

  int* randCount = calloc(1, sizeof(int));
  int* countY = calloc(1, sizeof(int));

  unsigned char* results[2];
  results[0] = calloc(32, sizeof(unsigned char));
  results[1] = calloc(32, sizeof(unsigned char));

  unsigned char* w[2];
  w[0] = calloc(input_len, sizeof(unsigned char));
  w[1] = calloc(input_len, sizeof(unsigned char));

  memcpy(w[0], z.ve.x, input_len);
  memcpy(w[1], z.ve1.x, input_len);

  mpc_sha256_padded(results, w, z, input_len * 8, randomness, randCount, countY, 0);

  free_array(2, randomness);
  free_array(2, w);

  free_array(2, results);

  free(randCount);
  free(countY);

  return 0;
}

int main(void) {
  setbuf(stdout, NULL);
  init_EVP();
  openmp_thread_setup();

  printf("Iterations of SHA: %d\n", NUM_ROUNDS);

  clock_t begin = clock(), delta, deltaFiles;

  a as[NUM_ROUNDS];
  z zs[NUM_ROUNDS];
  FILE* file;
  clock_t t_all = clock();
  char outputFile[20];
  sprintf(outputFile, "out%i.bin", NUM_ROUNDS);
  file = fopen(outputFile, "rb");
  if (!file) {
    printf("Unable to open file!");
  }
  fread(&as, sizeof(a), NUM_ROUNDS, file);
  fread(&zs, sizeof(z), NUM_ROUNDS, file);
  fclose(file);

  uint8_t y[OUTPUT_LEN];
  reconstruct(as[0].yp[0], as[0].yp[1], as[0].yp[2], y);
  // Printing output
  printf("Input state: ");
	for (int i = STATE_LEN; i < OUTPUT_LEN; i++) {
		printf("%02X", y[i]);
	}
	printf("\n");

  printf("Output state: ");
	for (int i = 0; i < STATE_LEN; i++) {
		printf("%02X", y[i]);
	}
	printf("\n");

  deltaFiles = clock() - begin;
  int inMilliFiles = deltaFiles * 1000 / CLOCKS_PER_SEC;
  printf("Loading files: %ju\n", (uintmax_t)inMilliFiles);

  clock_t beginE = clock(), deltaE;
  int es[NUM_ROUNDS];
  H3(y, as, NUM_ROUNDS, es);
  deltaE = clock() - beginE;
  int inMilliE = deltaE * 1000 / CLOCKS_PER_SEC;
  printf("Generating E: %ju\n", (uintmax_t)inMilliE);

  clock_t beginV = clock(), deltaV;
#pragma omp parallel for
  for (int i = 0; i < NUM_ROUNDS; i++) {
    int verifyResult = verify(as[i], es[i], zs[i]);
    if (verifyResult != 0) {
      printf("Not Verified %d\n", i);
    }
  }
  deltaV = clock() - beginV;
  int inMilliV = deltaV * 1000 / CLOCKS_PER_SEC;
  printf("Verifying: %ju\n", (uintmax_t)inMilliV);

  clock_t t_all_delta = clock() - t_all;
  printf("total time %ju us\n",
         (uintmax_t)t_all_delta * 1000 * 1000 / CLOCKS_PER_SEC);

  delta = clock() - begin;
  int inMilli = delta * 1000 / CLOCKS_PER_SEC;

  printf("Total time: %ju\n", (uintmax_t)inMilli);

  openmp_thread_cleanup();
  cleanup_EVP();
  return EXIT_SUCCESS;
}
