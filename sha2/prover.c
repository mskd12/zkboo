/*
 ============================================================================
 Name        : MPC_SHA256.c
 Author      : Sobuno
 Version     : 0.1
 Description : MPC SHA256 for one block only
 ============================================================================
 */

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include "aes.h"
#include "omp.h"
#include "shared.h"
#include "zklib.h"

uint8_t USERNAME[] = {0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
                      0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38};

int mpc_sha256(unsigned char *results[3], unsigned char *inputs[3], int numBits,
							 unsigned char *randomness[3], int *randCount, View views[3],
							 int *countY, int view_idx) {
	int used_len = 0;
	clock_t t_begin;
	int chars = numBits >> 3;

	unsigned char *chunks;
	uint32_t w[64][3];
	uint32_t a[3], b[3], c[3], d[3], e[3], f[3], g[3], h[3];
	uint32_t s0[3], s1[3];
	uint32_t t0[3], t1[3];

	uint32_t ctx[8][3] = {{hA[0], hA[0], hA[0]}, {hA[1], hA[1], hA[1]},
												{hA[2], hA[2], hA[2]}, {hA[3], hA[3], hA[3]},
												{hA[4], hA[4], hA[4]}, {hA[5], hA[5], hA[5]},
												{hA[6], hA[6], hA[6]}, {hA[7], hA[7], hA[7]}};

	int wi = 0;

	int block_no = ((chars + 8) / 64) + 1;
	// printf("hmac num blocks: %d\n", block_no);
	bool setOne[3] = {false, false, false};
	used_len = 64 * block_no;
	for (int rd = 0; rd < block_no; rd++) {
		t_begin = clock();
		int count_s = *countY;
		int blk = chars < 64 ? chars : 64;
		// pre-process input into chunks
		for (int i = 0; i < 3; i++) {
			chunks = calloc(64, sizeof(unsigned char));

			memcpy(chunks, inputs[i] + 64 * rd, blk);

			if (blk < 56) {
				if (!setOne[i]) {
					chunks[blk] = 0x80;
					setOne[i] = true;
				}

        // set length
				chunks[63] = numBits & 0xff;
				chunks[62] = (numBits >> 8) & 0xff;
				chunks[61] = (numBits >> 16) & 0xff;
				chunks[60] = (numBits >> 24) & 0xff;
			}
			else if (blk >= 56 && blk < 64) {
        chunks[blk] = 0x80;
        setOne[i] = true;
			}

			wi += blk;

			for (int j = 0; j < 16; j++) {
				w[j][i] = (chunks[j * 4] << 24) | (chunks[j * 4 + 1] << 16) |
									(chunks[j * 4 + 2] << 8) | chunks[j * 4 + 3];
			}

			free(chunks);
		}

		for (int j = 16; j < 64; j++) {
			mpc_RIGHTROTATE(w[j - 15], 7, t0);

			mpc_RIGHTROTATE(w[j - 15], 18, t1);
			mpc_XOR(t0, t1, t0);
			mpc_RIGHTSHIFT(w[j - 15], 3, t1);
			mpc_XOR(t0, t1, s0);

			mpc_RIGHTROTATE(w[j - 2], 17, t0);
			mpc_RIGHTROTATE(w[j - 2], 19, t1);

			mpc_XOR(t0, t1, t0);
			mpc_RIGHTSHIFT(w[j - 2], 10, t1);
			mpc_XOR(t0, t1, s1);

			mpc_ADD(w[j - 16], s0, t1, randomness, randCount, views, countY);

			mpc_ADD(w[j - 7], t1, t1, randomness, randCount, views, countY);
			mpc_ADD(t1, s1, w[j], randomness, randCount, views, countY);
		}

		memcpy(a, ctx[0], sizeof(a));
		memcpy(b, ctx[1], sizeof(b));
		memcpy(c, ctx[2], sizeof(c));
		memcpy(d, ctx[3], sizeof(d));
		memcpy(e, ctx[4], sizeof(e));
		memcpy(f, ctx[5], sizeof(f));
		memcpy(g, ctx[6], sizeof(g));
		memcpy(h, ctx[7], sizeof(h));

		uint32_t temp1[3], temp2[3], maj[3];
		for (int i = 0; i < 64; i++) {
			// s1 = RIGHTROTATE(e,6) ^ RIGHTROTATE(e,11) ^ RIGHTROTATE(e,25);
			mpc_RIGHTROTATE(e, 6, t0);
			mpc_RIGHTROTATE(e, 11, t1);
			mpc_XOR(t0, t1, t0);

			mpc_RIGHTROTATE(e, 25, t1);
			mpc_XOR(t0, t1, s1);

			mpc_ADD(h, s1, t0, randomness, randCount, views, countY);

			mpc_CH(e, f, g, t1, randomness, randCount, views, countY);
			mpc_ADD(t0, t1, t1, randomness, randCount, views, countY);
			mpc_ADDK(t1, k[i], t1, randomness, randCount, views, countY);

			mpc_ADD(t1, w[i], temp1, randomness, randCount, views, countY);

			mpc_RIGHTROTATE(a, 2, t0);
			mpc_RIGHTROTATE(a, 13, t1);
			mpc_XOR(t0, t1, t0);
			mpc_RIGHTROTATE(a, 22, t1);
			mpc_XOR(t0, t1, s0);

			mpc_MAJ(a, b, c, maj, randomness, randCount, views, countY);

			mpc_ADD(s0, maj, temp2, randomness, randCount, views, countY);

			memcpy(h, g, sizeof(uint32_t) * 3);
			memcpy(g, f, sizeof(uint32_t) * 3);
			memcpy(f, e, sizeof(uint32_t) * 3);

			mpc_ADD(d, temp1, e, randomness, randCount, views, countY);
			memcpy(d, c, sizeof(uint32_t) * 3);
			memcpy(c, b, sizeof(uint32_t) * 3);
			memcpy(b, a, sizeof(uint32_t) * 3);

			mpc_ADD(temp1, temp2, a, randomness, randCount, views, countY);
		}

		mpc_ADD(ctx[0], a, ctx[0], randomness, randCount, views, countY);
		mpc_ADD(ctx[1], b, ctx[1], randomness, randCount, views, countY);
		mpc_ADD(ctx[2], c, ctx[2], randomness, randCount, views, countY);
		mpc_ADD(ctx[3], d, ctx[3], randomness, randCount, views, countY);
		mpc_ADD(ctx[4], e, ctx[4], randomness, randCount, views, countY);
		mpc_ADD(ctx[5], f, ctx[5], randomness, randCount, views, countY);
		mpc_ADD(ctx[6], g, ctx[6], randomness, randCount, views, countY);
		mpc_ADD(ctx[7], h, ctx[7], randomness, randCount, views, countY);
		chars -= blk;

		// printf("sha256 1 block time %ju us\n", (uintmax_t)(clock() - t_begin) *
		// 1000 * 1000/ CLOCKS_PER_SEC); printf("sha256 1 block gates %d\n", *countY
		// - count_s);
	}

	// exit(0);

	for (int i = 0; i < 8; i++) {
		mpc_RIGHTSHIFT(ctx[i], 24, t0);
		results[0][i * 4] = t0[0];
		results[1][i * 4] = t0[1];
		results[2][i * 4] = t0[2];
		mpc_RIGHTSHIFT(ctx[i], 16, t0);
		results[0][i * 4 + 1] = t0[0];
		results[1][i * 4 + 1] = t0[1];
		results[2][i * 4 + 1] = t0[2];
		mpc_RIGHTSHIFT(ctx[i], 8, t0);
		results[0][i * 4 + 2] = t0[0];
		results[1][i * 4 + 2] = t0[1];
		results[2][i * 4 + 2] = t0[2];

		results[0][i * 4 + 3] = ctx[i][0];
		results[1][i * 4 + 3] = ctx[i][1];
		results[2][i * 4 + 3] = ctx[i][2];
	}

	return used_len;
}

a commit(int numBytes, unsigned char *shares[3], unsigned char *randomness[3],
         unsigned char rs[3][4], View views[3]) {
  uint8_t *inputs[3];
  inputs[0] = shares[0];
  inputs[1] = shares[1];
  inputs[2] = shares[2];

  uint8_t *cipher[3];
  uint8_t *result[3];
  int out_len = 32;

  for (int i = 0; i < 3; i++) {
    cipher[i] = calloc(out_len, sizeof(uint8_t));
    result[i] = calloc(out_len, sizeof(uint8_t));
  }

  int *countY = calloc(1, sizeof(int));
  int *randCount = calloc(1, sizeof(int));

  memcpy(views[0].x, inputs[0], numBytes);
  memcpy(views[1].x, inputs[1], numBytes);
  memcpy(views[2].x, inputs[2], numBytes);

  mpc_sha256(cipher, inputs, numBytes * 8, randomness, randCount, views, countY, 0);

  memcpy(&views[0].y[*countY], cipher[0], out_len);
  memcpy(&views[1].y[*countY], cipher[1], out_len);
  memcpy(&views[2].y[*countY], cipher[2], out_len);
  *countY += out_len / 4;

  printf("Number of gates: %d\n", *countY);
  printf("Number of randomness: %d\n", *randCount);

  a a;
  for (int i = 0; i < 3; i++) {
    output_var(views[i], result[i], out_len);
    memcpy(a.yp[i], result[i], out_len);
  }

  free_array(3, result);
  free_array(3, cipher);
  free(countY);
  free(randCount);

  return a;
}

z prove(int e, unsigned char keys[3][16], unsigned char rs[3][4],
        View views[3]) {
  z z;
  // printf("e: %d\n", e);
  memcpy(z.ke, keys[e], 16);
  memcpy(z.ke1, keys[(e + 1) % 3], 16);
  z.ve = views[e];
  z.ve1 = views[(e + 1) % 3];
  memcpy(z.re, rs[e], 4);
  memcpy(z.re1, rs[(e + 1) % 3], 4);

  return z;
}

int main() {
  srand((unsigned)time(NULL));
  init_EVP();
  openmp_thread_setup();
  printf("Clock per sec %ld\n", CLOCKS_PER_SEC);

  unsigned char garbage[4];
  if (RAND_bytes(garbage, 4) != 1) {
    printf("RAND_bytes failed crypto, aborting\n");
    return 0;
  }

  int input_len = USER_INPUT_LEN;

  printf("String length: %d\n", input_len);
  printf("Iterations of SHA: %d\n", NUM_ROUNDS);

  uint8_t input[input_len];
  memset(input, 0, input_len);

  memcpy(input, USERNAME, USER_INPUT_LEN);

  printf("Input: ");
  for (int i = 0; i < USER_INPUT_LEN; i++)
  {
    printf("%02X", USERNAME[i]);
  }
  printf("\n");

  clock_t t_all = clock();

  a as[NUM_ROUNDS];
  z *zs = calloc(NUM_ROUNDS, sizeof(z));

  int es[NUM_ROUNDS];

  unsigned char keys[NUM_ROUNDS][3][16];
  unsigned char rs[NUM_ROUNDS][3][4];

  //	View localViews[NUM_ROUNDS][3];

  View *localViews[NUM_ROUNDS];
  for (int i = 0; i < NUM_ROUNDS; i++) {
    localViews[i] = calloc(sizeof(View), 3);
  }

  unsigned char *randomness[3];
  randomness[0] = calloc(RANDOMNESS_LEN, sizeof(unsigned char));
  randomness[1] = calloc(RANDOMNESS_LEN, sizeof(unsigned char));
  randomness[2] = calloc(RANDOMNESS_LEN, sizeof(unsigned char));

  for (int rd_no = 0; rd_no < NUM_ROUNDS; rd_no++) {
    printf("Round %d\n", rd_no);

    // Generating keys
    for (int i = 0; i < 3; i++) {
      if (RAND_bytes(keys[rd_no][i], 16) != 1) {
        printf("RAND_bytes failed crypto, aborting\n");
        return 0;
      }

      if (RAND_bytes(rs[rd_no][i], 4) != 1) {
        printf("RAND_bytes failed crypto, aborting\n");
        return 0;
      }
    }

    // Sharing secrets
    unsigned char *shares[3];
    for (int i = 0; i < 3; i++) {
      shares[i] = calloc(input_len, sizeof(unsigned char));
      if (RAND_bytes(shares[i], input_len) != 1) {
        printf("RAND_bytes failed crypto, aborting\n");
        return 0;
      }
    }

    // #pragma omp parallel for
    for (int i = 0; i < input_len; i++) {
      shares[2][i] = input[i] ^ shares[0][i] ^ shares[1][i];
    }

    // #pragma omp parallel for
    for (int i = 0; i < 3; i++) {
      // randomness[i] = calloc(RANDOMNESS_LEN, sizeof(unsigned char));
      get_all_randomness(keys[rd_no][i], randomness[i]);
    }

    // Running MPC-SHA2
    as[rd_no] =
        commit(input_len, shares, randomness, rs[rd_no], localViews[rd_no]);

    //
    free_array(3, shares);

    // Committing
    unsigned char digest[SHA256_DIGEST_LENGTH];
    // #pragma omp parallel for
    for (int i = 0; i < 3; i++) {
      H(keys[rd_no][i], localViews[rd_no][i], rs[rd_no][i], digest);
      memcpy(as[rd_no].h[i], digest, 32);
    }

    uint8_t yy[32];
    reconstruct(as[rd_no].yp[0], as[rd_no].yp[1], as[rd_no].yp[2], yy);
    printf("Output: ");
    for (int i = 0; i < 32; i++) {
      printf("%02X", yy[i]);
    }
    printf("\n");
  }

  free_array(3, randomness);
  // Generating E
  uint8_t finalHash[32];
  for (int i = 0; i < 32; i++) {
    finalHash[i] = as[0].yp[0][i] ^ as[0].yp[1][i] ^ as[0].yp[2][i];
  }
  H3(finalHash, as, NUM_ROUNDS, es);

  // Packing Z
  //#pragma omp parallel for
  for (int i = 0; i < NUM_ROUNDS; i++) {
    zs[i] = prove(es[i], keys[i], rs[i], localViews[i]);
  }

  printf("before output time %ju us\n",
         (uintmax_t)(clock() - t_all) * 1000 * 1000 / CLOCKS_PER_SEC);
  // Writing to file

  FILE *file;
  char outputFile[20];
  sprintf(outputFile, "out%i.bin", NUM_ROUNDS);
  file = fopen(outputFile, "wb");
  if (!file) {
    printf("Unable to open file!");
    return 1;
  }
  fwrite(as, sizeof(a), NUM_ROUNDS, file);
  fwrite(zs, sizeof(z), NUM_ROUNDS, file);

  fclose(file);
  free(zs);
  clock_t t_all_delta = clock() - t_all;
  printf("total time %ju us\n",
         (uintmax_t)t_all_delta * 1000 * 1000 / CLOCKS_PER_SEC);

  for (int i = 0; i < NUM_ROUNDS; i++) {
    free(localViews[i]);
  }

  openmp_thread_cleanup();
  cleanup_EVP();
  return EXIT_SUCCESS;
}