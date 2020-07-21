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
#include "zklib.h"
#include "shared.h"
#include "omp.h"
#include "aes.h"




// hmac key
uint8_t HMAC_KEY[] = {
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
	0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22
};

// aes key
uint8_t AES_KEY[] = {
	0x11,0x11,0x11,0x11,0x11,0x11,0x11, 0xaa, 0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa
};

uint8_t IV[] = {
	0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x05, 0x05, 0x00, 0x30, 0x3a, 0x31, 0x19, 0x30
};

uint8_t USERNAME[] = {
	0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
	0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38
};

uint8_t PUBKEY[] = {
	0xb4, 0x68, 0xe7, 0xc4, 0xef, 0x57, 0xea, 0xa6, 0xca, 0x55, 0x17, 0xc5, 0x9b, 0xb9, 0x67, 0xc1, 
	0xde, 0x0f, 0xb6, 0x36, 0x47, 0x44, 0xeb, 0xe9, 0x98, 0x41, 0xb7, 0x0b, 0xbd, 0x57, 0x1c, 0xe5, 
	0x61, 0x7b, 0xcb, 0x76, 0x6b, 0xfa, 0x52, 0x6e, 0x14, 0x2e, 0x7e, 0xd1, 0x08, 0xaf, 0x5e, 0xda, 
	0xe3, 0xad, 0xa3, 0xd6, 0x95, 0x4d, 0xbf, 0x2d, 0x73, 0x7c, 0xb0, 0x91, 0x87, 0x19, 0xcd, 0x1a, 
	0x84, 0x51, 0x84, 0x7d, 0x57, 0xa5, 0xb6, 0x74, 0xf1, 0xa6, 0xe7, 0x35, 0xb0, 0x48, 0xee, 0x23, 
	0xc5, 0xe4, 0x6b, 0xe1, 0xdc, 0xd1, 0x62, 0x23, 0xea, 0xe0, 0x37, 0xc6, 0xcf, 0xac, 0x01, 0x2a, 
	0x34, 0x92, 0xbd, 0x40, 0xc8, 0xfe, 0x30, 0xff, 0x70, 0x82, 0x4b, 0xf7, 0xfe, 0x9a, 0x46, 0x40, 
	0x75, 0x86, 0x12, 0x9e, 0x3e, 0x1f, 0xb2, 0x5b, 0x2b, 0xb7, 0x0d, 0x3a, 0xee, 0x99, 0x85, 0x85, 
	0xb4, 0x68, 0xe7, 0xc4, 0xef, 0x57, 0xea, 0xa6, 0xca, 0x55, 0x17, 0xc5, 0x9b, 0xb9, 0x67, 0xc1, 
	0xde, 0x0f, 0xb6, 0x36, 0x47, 0x44, 0xeb, 0xe9, 0x98, 0x41, 0xb7, 0x0b, 0xbd, 0x57, 0x1c, 0xe5, 
	0x61, 0x7b, 0xcb, 0x76, 0x6b, 0xfa, 0x52, 0x6e, 0x14, 0x2e, 0x7e, 0xd1, 0x08, 0xaf, 0x5e, 0xda, 
	0xe3, 0xad, 0xa3, 0xd6, 0x95, 0x4d, 0xbf, 0x2d, 0x73, 0x7c, 0xb0, 0x91, 0x87, 0x19, 0xcd, 0x1a, 
	0x84, 0x51, 0x84, 0x7d, 0x57, 0xa5, 0xb6, 0x74, 0xf1, 0xa6, 0xe7, 0x35, 0xb0, 0x48, 0xee, 0x23, 
	0xc5, 0xe4, 0x6b, 0xe1, 0xdc, 0xd1, 0x62, 0x23, 0xea, 0xe0, 0x37, 0xc6, 0xcf, 0xac, 0x01, 0x2a, 
	0x34, 0x92, 0xbd, 0x40, 0xc8, 0xfe, 0x30, 0xff, 0x70, 0x82, 0x4b, 0xf7, 0xfe, 0x9a, 0x46, 0x40, 
	0x75, 0x86, 0x12, 0x9e, 0x3e, 0x1f, 0xb2, 0x5b, 0x2b, 0xb7, 0x0d, 0x3a, 0xee, 0x99, 0x85, 0x85
};





int mpc_sha256(unsigned char* results[3], unsigned char* inputs[3], int numBits, unsigned char *randomness[3],  int* randCount, View views[3], int* countY, int view_idx) {

	int used_len = 0;
	clock_t t_begin;
	int chars = numBits >> 3;

	unsigned char* chunks;
	uint32_t w[64][3];
	uint32_t a[3], b[3], c[3], d[3], e[3], f[3], g[3], h[3];
	uint32_t s0[3], s1[3];
	uint32_t t0[3], t1[3];

	uint32_t ctx[8][3] = { { hA[0], hA[0], hA[0]  }, { hA[1], hA[1], hA[1] }, { hA[2], hA[2], hA[2] },
		{ hA[3], hA[3], hA[3] }, { hA[4], hA[4], hA[4] }, { hA[5], hA[5], hA[5] },
		{ hA[6], hA[6], hA[6] }, { hA[7], hA[7], hA[7] }
	};

	int wi = 0;

	int block_no = ((chars + 8) / 64) + 1;
	// printf("hmac block no %d\n", block_no);

	//printf("SHA256 no of blk opers %d\n", block_no);
	//printf("%d, %d\n", *countY, *randCount);
	bool setOne = false;
	used_len = 64 * block_no;
	for (int rd = 0; rd < block_no; rd++){
		t_begin = clock();
		int count_s = *countY;
		int blk = chars < 64 ? chars : 64;
		// pre-process input into chunks
		for (int i = 0; i < 3; i++) {

			chunks = calloc(64, sizeof(unsigned char));

			memcpy(chunks, inputs[i] + 64 * rd, blk);

			// inputs[i] += blk;

			if (blk < 56) {
				if (!setOne) {
					chunks[blk] = 0x80;
					setOne = true;
				}

				chunks[63] = numBits & 0xff;
				chunks[62] = (numBits >> 8) & 0xff;
				// chunks[61] = (numBits >> 16) & 0xff;
				// chunks[60] = (numBits >> 24) & 0xff;
			}
			else if (blk >= 56 && blk < 64) {
				chunks[blk] = 0x80;
				setOne = true;
			}

		
	
			// memcpy(views[i].xv + view_idx + 64 * rd, chunks, 64);
			// if (view_idx==384) {

			// // 	
			// 	printf("start--------------%d\n", view_idx + 64 * rd);
				
			// // 	printf("%d\n", i);
			// // 	print_hex(chunks, 64);
			// 	printf("%d\n", i);
			// 	print_hex(inputs[i], 64);
			// print_hex_info(chunks, 64, "sha256 chunks");
			// 	printf("end--------------\n");
				
			// }
			// if (rd == 0)
			//  {print_hex_info(chunks, 64, "sha256 chunks");}
			
			wi += blk;

			for (int j = 0; j < 16; j++) {
				w[j][i] = (chunks[j * 4] << 24) | (chunks[j * 4 + 1] << 16)
				          | (chunks[j * 4 + 2] << 8) | chunks[j * 4 + 3];
			}

			free(chunks);
		}

		// printf("--------\n");

		// if (rd == 0) {
		// print_hex_info(w[0], 64, "sha256 w1");
		// print_hex_info(w[1], 64, "sha256 w2");
		// print_hex_info(w[2], 64, "sha256 w3");
		// }

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

			// if ((view_idx==384) && (j == 16)) {

			// printf("!!!!\n");
			// print_hex(w[j-16], 64);
			// }
			// printf("%d\n", *randCount);
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
			//s1 = RIGHTROTATE(e,6) ^ RIGHTROTATE(e,11) ^ RIGHTROTATE(e,25);
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


		// printf("sha256 1 block time %ju us\n", (uintmax_t)(clock() - t_begin) * 1000 * 1000/ CLOCKS_PER_SEC);
		// printf("sha256 1 block gates %d\n", *countY - count_s);
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


int
hmac_sha256(unsigned char* results[3], unsigned char* inputs[3], int numBits, unsigned char *randomness[3],  int* randCount, View views[3], int* countY, int view_idx)
{

	// first 32 bytes is key, the rest are data
	int chars = numBits >> 3;

	unsigned char k_ipad[3][65];
	unsigned char k_opad[3][65];

	unsigned char key[3][32];
	unsigned char msg[3][1024];

	int key_len = 32;
	int msg_len = chars - 32;

	unsigned char buf[3][1024];
	unsigned char* pbuf[3];



	for (int i = 0; i < 3; i++) {
		bzero(buf[i], 1024);
		memcpy(key[i], inputs[i], key_len);
		memcpy(msg[i], inputs[i] + key_len, msg_len);

		memset( k_ipad[i], 0, sizeof(k_ipad[i]));
		memset( k_opad[i], 0, sizeof(k_opad[i]));
		memcpy( k_ipad[i], key[i], key_len);
		memcpy( k_opad[i], key[i], key_len);

		for (int j = 0; j < 64; j++) {
			k_ipad[i][j] ^= 0x36;
			k_opad[i][j] ^= 0x5c;
		}

		for (int j = 0; j < 64; j++) {
			buf[i][j] = k_ipad[i][j];
		}

		for (int j = 0; j < msg_len; j++) {
			buf[i][j + 64] = msg[i][j];
		}

		pbuf[i] = buf[i];
	}

	int used_len = 0;


	printf("HMAC raw msg (size = %d): \n", msg_len);

	for (int i = 0; i < msg_len; i++) {
		printf("%02X", msg[0][i] ^ msg[1][i] ^ msg[2][i]);
	}

	printf("\n");

	view_idx += mpc_sha256(results, pbuf, (msg_len + 64) * 8, randomness, randCount, views, countY, view_idx);



	for (int i = 0; i < 3; i++) {
		bzero(buf[i], 1024);
		for (int j = 0; j < 64; j++) {
			buf[i][j] = k_opad[i][j];
		}
		for (int j = 0; j < SHA256_DIGEST_LENGTH; j++) {
			buf[i][j + 64] = results[i][j];
		}
		pbuf[i] = buf[i];

	}

	// printf("results\n");
	// print_hex(pbuf[0], 64);
	// print_hex(pbuf[1], 64);
	// print_hex(pbuf[2], 64);
	// printf("results end\n");

	view_idx += mpc_sha256(results, pbuf, (SHA256_DIGEST_LENGTH + 64) * 8, randomness,  randCount, views, countY, view_idx);

	// printf("results\n");
	// print_hex(results[0], 64);
	// print_hex(results[1], 64);
	// print_hex(results[2], 64);
	// printf("results end\n");

	return view_idx;

}




void hmac_test(unsigned char* results[3], unsigned char* inputs[3], int numBytes, unsigned char *randomness[3], int *randCount,  View views[3], int* countY) {

	// input: IV, aes key, hmac key, msg, pubkey
	// tls part



	
	int test_len = 2 * 184 - 152 - 2 ;

	uint8_t* hmac_input[3];
	uint8_t* hmac_tag[3];


	clock_t t_begin = clock();

	// init 
	for (int i = 0; i < 3; i++) {
		//hard coded
		hmac_input[i] = calloc(test_len, sizeof(uint8_t));
		hmac_tag[i] = calloc(32, sizeof(uint8_t));

	}
	
	

	// prepare hmac inputs
	for (int i = 0; i < test_len; i++) {
		hmac_input[0][i] = inputs[0][i];
		hmac_input[1][i] = inputs[1][i];
		hmac_input[2][i] = inputs[2][i];
	}
	

	// memcpy(input, IV, 16);
	// memcpy(input + 16, ex_keys, 176);
	// memcpy(input + 16 + 176, HMAC_KEY, 32);
	// memcpy(input + 16 + 176 + 32, USERNAME, 32);
	// memcpy(input + 16 + 176 + 32 + 32, PUBKEY, 256);



	printf("tls input prepare time %ju us\n", (uintmax_t)(clock() - t_begin) * 1000* 1000 / CLOCKS_PER_SEC);
	
	t_begin = clock();
	
	int view_idx = 0;

	hmac_sha256(hmac_tag, hmac_input, test_len * 8, randomness, randCount, views, countY, view_idx);
	

	uint8_t yy[32];
	reconstruct(hmac_tag[0], hmac_tag[1], hmac_tag[2], yy);
	printf("HMAC tag: ");
	for (int i = 0; i < 32; i++) {
		printf("%02X", yy[i]);
	}
	printf("\n");


	printf("tls hmac time %ju us, %d\n", (uintmax_t)(clock() - t_begin) * 1000* 1000 / CLOCKS_PER_SEC, *countY);
	


	free_array(3, hmac_input);
	free_array(3, hmac_tag);
	
	// NEED TO FREE!!!!!!!
	
}


a commit(int numBytes, unsigned char* shares[3], unsigned char *randomness[3], unsigned char rs[3][4], View views[3]) {


	uint8_t* inputs[3];
	inputs[0] = shares[0];
	inputs[1] = shares[1];
	inputs[2] = shares[2];

	uint8_t* cipher[3];
	uint8_t* result[3];
	int out_len = 32;

	for (int i = 0; i < 3; i++){
		cipher[i] = calloc(out_len, sizeof(uint8_t));
		result[i] = calloc(out_len, sizeof(uint8_t));
	}


	// check_state("input", inputs, 64);
	// uint8_t yy[32];
	// 	reconstruct(inputs[0], inputs[1], inputs[2], yy);
	// 	printf("Proof for input: ");
	// 	for (int i = 0; i < 32; i++) {
	// 		printf("%02X", yy[i]);
	// 	}
	// 	printf("\n");


	int* countY = calloc(1, sizeof(int));
	int* randCount = calloc(1, sizeof(int));

	memcpy(views[0].x, inputs[0], numBytes);
	memcpy(views[1].x, inputs[1], numBytes);
	memcpy(views[2].x, inputs[2], numBytes);


	// printf("inputs\n");
	// print_hex(randomness[0], 32);
	// print_hex(randomness[1], 32);
	// print_hex(randomness[2], 32);
	// printf("\n");

	hmac_test(cipher, inputs, numBytes, randomness, randCount, views, countY);

	// print_hex(views[0].xv, 512);
	// print_hex(views[1].xv, 512);
	// print_hex(views[2].xv, 512);

	memcpy(&views[0].y[*countY], cipher[0], out_len);
	memcpy(&views[1].y[*countY], cipher[1], out_len);
	memcpy(&views[2].y[*countY], cipher[2], out_len);
	*countY += out_len / 4;



	printf("Number of gates: %d\n", *countY);
	printf("Number of randomness: %d\n", *randCount);

	

	

	a a;
	for (int i = 0; i < 3; i++){
		output_var(views[i], result[i], out_len);
		memcpy(a.yp[i], result[i], out_len);
	}
	
	free_array(3, result);
	free_array(3, cipher);
	free(countY);
	free(randCount);
	

	return a;
}

z prove(int e, unsigned char keys[3][16], unsigned char rs[3][4], View views[3]) {
	z z;
	memcpy(z.ke, keys[e], 16);
	memcpy(z.ke1, keys[(e + 1) % 3], 16);
	z.ve = views[e];
	z.ve1 = views[(e + 1) % 3];
	memcpy(z.re, rs[e], 4);
	memcpy(z.re1, rs[(e + 1) % 3], 4);

	return z;
}

/***
private: username = "1234567812345678"
private: hmac key = hmac_key
private: aes key = aes_key
private: IV = IV
public: tls record = tls_record
public: x509 cert hash = cert_hash
1. inputs: a certficate, hash of certficate

***/


int main(void) {
	srand((unsigned) time(NULL));
	init_EVP();
	openmp_thread_setup();
	printf("Clock per sec %ld\n", CLOCKS_PER_SEC);

	//
	unsigned char garbage[4];
	if (RAND_bytes(garbage, 4) != 1) {
		printf("RAND_bytes failed crypto, aborting\n");
		return 0;
	}

	int input_len = 32 * 2 + 256 * 2;

	printf("String length: %d\n", input_len);
	printf("Iterations of SHA: %d\n", NUM_ROUNDS);

	uint8_t input[input_len];
	memset(input, 0, input_len);

	//Nb * (Nr + 1) * 4 = 176
	uint8_t ex_keys[176];

	//key expansion
	key_expansion(AES_KEY, ex_keys);


	print_hex(HMAC_KEY, 32);

	memcpy(input, HMAC_KEY, 32);
	memcpy(input + 32, USERNAME, 32);
	memcpy(input + 32 + 32, PUBKEY, 256);
	memcpy(input + 32 + 32 + 256, PUBKEY, 256);

	clock_t t_all = clock();
	
	a as[NUM_ROUNDS];
	z* zs = calloc(NUM_ROUNDS, sizeof(z));
	//z zs[NUM_ROUNDS];

	int es[NUM_ROUNDS];

	unsigned char keys[NUM_ROUNDS][3][16];
	unsigned char rs[NUM_ROUNDS][3][4];
	View localViews[NUM_ROUNDS][3];

	unsigned char *randomness[3];
	randomness[0] = calloc(RANDOMNESS_LEN, sizeof(unsigned char));
	randomness[1] = calloc(RANDOMNESS_LEN, sizeof(unsigned char));
	randomness[2] = calloc(RANDOMNESS_LEN, sizeof(unsigned char));

	// unsigned char* xv_buf[3];
	// xv_buf[0] = (unsigned char*) calloc(2048, sizeof(unsigned char));
	// xv_buf[1] = (unsigned char*) calloc(2048, sizeof(unsigned char));
	// xv_buf[2] = (unsigned char*) calloc(2048, sizeof(unsigned char));

	for (int rd_no = 0; rd_no < NUM_ROUNDS; rd_no++)
	{	
		
		printf("Round %d\n", rd_no);

		//Generating keys
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

		//Sharing secrets
		unsigned char* shares[3];
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

		
		//Running MPC-SHA2
		as[rd_no] = commit(input_len, shares, randomness, rs[rd_no], localViews[rd_no]);	
		
		// 
		free_array(3, shares);



		//Committing
		unsigned char digest[SHA256_DIGEST_LENGTH];
		// #pragma omp parallel for
		for (int i = 0; i< 3; i++) {
			H(keys[rd_no][i], localViews[rd_no][i], rs[rd_no][i], digest);
			memcpy(as[rd_no].h[i], digest, 32);
			
		}

		uint8_t yy[32];
		reconstruct(as[rd_no].yp[0], as[rd_no].yp[1], as[rd_no].yp[2], yy);
		printf("Proof for hash: ");
		for (int i = 0; i < 32; i++) {
			printf("%02X", yy[i]);
		}
		printf("\n");

		
	}


	free_array(3, randomness);
	//Generating E
	uint8_t finalHash[32];
	for (int i = 0; i < 32; i++) {
		finalHash[i] = as[0].yp[0][i] ^ as[0].yp[1][i] ^ as[0].yp[2][i];
	}
	H3(finalHash, as, NUM_ROUNDS, es);

	
	//Packing Z
	//#pragma omp parallel for
	for(int i = 0; i<NUM_ROUNDS; i++) {
		zs[i] = prove(es[i],keys[i],rs[i], localViews[i]);
	}
	
	printf("before output time %ju us\n", (uintmax_t)(clock() - t_all) * 1000 * 1000/ CLOCKS_PER_SEC);
	//Writing to file
	
	FILE *file;
	char outputFile[10];
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
	printf("total time %ju us\n", (uintmax_t)t_all_delta * 1000 * 1000 / CLOCKS_PER_SEC);
	
	
	openmp_thread_cleanup();
	cleanup_EVP();
	return EXIT_SUCCESS;
}
