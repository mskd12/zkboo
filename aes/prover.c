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

uint8_t mpc_small_sbox(uint8_t state[3], uint8_t n[3],
                       unsigned char *randomness[3], int *randCount,
                       View views[3], int *countY) {
  uint8_t U0[3], U1[3], U2[3], U3[3], U4[3], U5[3], U6[3], U7[3];
  uint8_t T1[3], T2[3], T3[3], T4[3], T5[3], T6[3], T7[3], T8[3];
  uint8_t T9[3], T10[3], T11[3], T12[3], T13[3], T14[3], T15[3], T16[3];
  uint8_t T17[3], T18[3], T19[3], T20[3], T21[3], T22[3], T23[3], T24[3];
  uint8_t T25[3], T26[3], T27[3];
  uint8_t M1[3], M2[3], M3[3], M4[3], M5[3], M6[3], M7[3], M8[3];
  uint8_t M9[3], M10[3], M11[3], M12[3], M13[3], M14[3], M15[3], M16[3];
  uint8_t M17[3], M18[3], M19[3], M20[3], M21[3], M22[3], M23[3], M24[3];
  uint8_t M25[3], M26[3], M27[3], M28[3], M29[3], M30[3], M31[3], M32[3];
  uint8_t M33[3], M34[3], M35[3], M36[3], M37[3], M38[3], M39[3], M40[3];
  uint8_t M41[3], M42[3], M43[3], M44[3], M45[3], M46[3], M47[3], M48[3];
  uint8_t M49[3], M50[3], M51[3], M52[3], M53[3], M54[3], M55[3], M56[3];
  uint8_t M57[3], M58[3], M59[3], M60[3], M61[3], M62[3], M63[3];
  uint8_t L0[3], L1[3], L2[3], L3[3], L4[3], L5[3], L6[3], L7[3];
  uint8_t L8[3], L9[3], L10[3], L11[3], L12[3], L13[3], L14[3], L15[3];
  uint8_t L16[3], L17[3], L18[3], L19[3], L20[3], L21[3], L22[3], L23[3];
  uint8_t L24[3], L25[3], L26[3], L27[3], L28[3], L29[3];
  uint8_t S0[3], S1[3], S2[3], S3[3], S4[3], S5[3], S6[3], S7[3];

  uint8_t buf[3];

  int count_s = *countY;
  // U0 = (n & ( 1 << 7 )) >> 7;
  mpc_ANDK_u8(n, (uint8_t)(1 << 7), buf, randomness, randCount, views, countY);
  mpc_RIGHTSHIFT_u8(buf, 7, U0);
  // U1 = (n & ( 1 << 6 )) >> 6;
  mpc_ANDK_u8(n, (uint8_t)(1 << 6), buf, randomness, randCount, views, countY);
  mpc_RIGHTSHIFT_u8(buf, 6, U1);
  // U2 = (n & ( 1 << 5 )) >> 5;
  mpc_ANDK_u8(n, (uint8_t)(1 << 5), buf, randomness, randCount, views, countY);
  mpc_RIGHTSHIFT_u8(buf, 5, U2);
  // U3 = (n & ( 1 << 4 )) >> 4;
  mpc_ANDK_u8(n, (uint8_t)(1 << 4), buf, randomness, randCount, views, countY);
  mpc_RIGHTSHIFT_u8(buf, 4, U3);
  // U4 = (n & ( 1 << 3 )) >> 3;
  mpc_ANDK_u8(n, (uint8_t)(1 << 3), buf, randomness, randCount, views, countY);
  mpc_RIGHTSHIFT_u8(buf, 3, U4);
  // U5 = (n & ( 1 << 2 )) >> 2;
  mpc_ANDK_u8(n, (uint8_t)(1 << 2), buf, randomness, randCount, views, countY);
  mpc_RIGHTSHIFT_u8(buf, 2, U5);
  // U6 = (n & ( 1 << 1 )) >> 1;
  mpc_ANDK_u8(n, (uint8_t)(1 << 1), buf, randomness, randCount, views, countY);
  mpc_RIGHTSHIFT_u8(buf, 1, U6);
  // U7 = (n & ( 1 << 0 )) >> 0;
  mpc_ANDK_u8(n, (uint8_t)(1 << 0), buf, randomness, randCount, views, countY);
  mpc_RIGHTSHIFT_u8(buf, 0, U7);

  // T1 = U0 ^ U3;
  mpc_XOR_u8(U0, U3, T1);
  // T2 = U0 ^ U5;
  mpc_XOR_u8(U0, U5, T2);
  // T3 = U0 ^ U6;
  mpc_XOR_u8(U0, U6, T3);
  // T4 = U3 ^ U5;
  mpc_XOR_u8(U3, U5, T4);
  // T5 = U4 ^ U6;
  mpc_XOR_u8(U4, U6, T5);
  // T6 = T1 ^ T5;
  mpc_XOR_u8(T1, T5, T6);
  // T7 = U1 ^ U2;
  mpc_XOR_u8(U1, U2, T7);
  // T8 = U7 ^ T6;
  mpc_XOR_u8(U7, T6, T8);
  // T9 = U7 ^ T7;
  mpc_XOR_u8(U7, T7, T9);
  // T10 = T6 ^ T7;
  mpc_XOR_u8(T6, T7, T10);
  // T11 = U1 ^ U5;
  mpc_XOR_u8(U1, U5, T11);
  // T12 = U2 ^ U5;
  mpc_XOR_u8(U2, U5, T12);
  // T13 = T3 ^ T4;
  mpc_XOR_u8(T3, T4, T13);
  // T14 = T6 ^ T11;
  mpc_XOR_u8(T6, T11, T14);
  // T15 = T5 ^ T11;
  mpc_XOR_u8(T5, T11, T15);
  // T16 = T5 ^ T12;
  mpc_XOR_u8(T5, T12, T16);
  // T17 = T9 ^ T16;
  mpc_XOR_u8(T9, T16, T17);
  // T18 = U3 ^ U7;
  mpc_XOR_u8(U3, U7, T18);
  // T19 = T7 ^ T18;
  mpc_XOR_u8(T7, T18, T19);
  // T20 = T1 ^ T19;
  mpc_XOR_u8(T1, T19, T20);
  // T21 = U6 ^ U7;
  mpc_XOR_u8(U6, U7, T21);
  // T22 = T7 ^ T21;
  mpc_XOR_u8(T7, T21, T22);
  // T23 = T2 ^ T22;
  mpc_XOR_u8(T2, T22, T23);
  // T24 = T2 ^ T10;
  mpc_XOR_u8(T2, T10, T24);
  // T25 = T20 ^ T17;
  mpc_XOR_u8(T20, T17, T25);
  // T26 = T3 ^ T16;
  mpc_XOR_u8(T3, T16, T26);
  // T27 = T1 ^ T12;
  mpc_XOR_u8(T1, T12, T27);

  // M1 = T13 & T6;
  mpc_AND_u8(T13, T6, M1, randomness, randCount, views, countY);
  // M2 = T23 & T8;
  mpc_AND_u8(T23, T8, M2, randomness, randCount, views, countY);

  // M3 = T14 ^ M1;
  mpc_XOR_u8(T14, M1, M3);
  // M4 = T19 & U7;
  mpc_AND_u8(T19, U7, M4, randomness, randCount, views, countY);
  // M5 = M4 ^ M1;
  mpc_XOR_u8(M4, M1, M5);
  // M6 = T3 & T16;
  mpc_AND_u8(T3, T16, M6, randomness, randCount, views, countY);
  // M7 = T22 & T9;
  mpc_AND_u8(T22, T9, M7, randomness, randCount, views, countY);
  // M8 = T26 ^ M6;
  mpc_XOR_u8(T26, M6, M8);
  // M9 = T20 & T17;
  mpc_AND_u8(T20, T17, M9, randomness, randCount, views, countY);
  // M10 = M9 ^ M6;
  mpc_XOR_u8(M9, M6, M10);
  // M11 = T1 & T15;
  mpc_AND_u8(T1, T15, M11, randomness, randCount, views, countY);
  // M12 = T4 & T27;
  mpc_AND_u8(T4, T27, M12, randomness, randCount, views, countY);
  // M13 = M12 ^ M11;
  mpc_XOR_u8(M12, M11, M13);
  // M14 = T2 & T10;
  mpc_AND_u8(T2, T10, M14, randomness, randCount, views, countY);
  // M15 = M14 ^ M11;
  mpc_XOR_u8(M14, M11, M15);
  // M16 = M3 ^ M2;
  mpc_XOR_u8(M3, M2, M16);
  // M17 = M5 ^ T24;
  mpc_XOR_u8(M5, T24, M17);
  // M18 = M8 ^ M7;
  mpc_XOR_u8(M8, M7, M18);
  // M19 = M10 ^ M15;
  mpc_XOR_u8(M10, M15, M19);
  // M20 = M16 ^ M13;
  mpc_XOR_u8(M16, M13, M20);

  // M21 = M17 ^ M15;
  mpc_XOR_u8(M17, M15, M21);
  // M22 = M18 ^ M13;
  mpc_XOR_u8(M18, M13, M22);
  // M23 = M19 ^ T25;
  mpc_XOR_u8(M19, T25, M23);
  // M24 = M22 ^ M23;
  mpc_XOR_u8(M22, M23, M24);
  // M25 = M22 & M20;
  mpc_AND_u8(M22, M20, M25, randomness, randCount, views, countY);
  // M26 = M21 ^ M25;
  mpc_XOR_u8(M21, M25, M26);
  // M27 = M20 ^ M21;
  mpc_XOR_u8(M20, M21, M27);
  // M28 = M23 ^ M25;
  mpc_XOR_u8(M23, M25, M28);
  // M29 = M28 & M27;
  mpc_AND_u8(M28, M27, M29, randomness, randCount, views, countY);
  // M30 = M26 & M24;
  mpc_AND_u8(M26, M24, M30, randomness, randCount, views, countY);
  // M31 = M20 & M23;
  mpc_AND_u8(M20, M23, M31, randomness, randCount, views, countY);
  // M32 = M27 & M31;
  mpc_AND_u8(M27, M31, M32, randomness, randCount, views, countY);
  // M33 = M27 ^ M25;
  mpc_XOR_u8(M27, M25, M33);
  // M34 = M21 & M22;
  mpc_AND_u8(M21, M22, M34, randomness, randCount, views, countY);
  // M35 = M24 & M34;
  mpc_AND_u8(M24, M34, M35, randomness, randCount, views, countY);
  // M36 = M24 ^ M25;
  mpc_XOR_u8(M24, M25, M36);
  // M37 = M21 ^ M29;
  mpc_XOR_u8(M21, M29, M37);
  // M38 = M32 ^ M33;
  mpc_XOR_u8(M32, M33, M38);
  // M39 = M23 ^ M30;
  mpc_XOR_u8(M23, M30, M39);
  // M40 = M35 ^ M36;
  mpc_XOR_u8(M35, M36, M40);
  // M41 = M38 ^ M40;
  mpc_XOR_u8(M38, M40, M41);
  // M42 = M37 ^ M39;
  mpc_XOR_u8(M37, M39, M42);
  // M43 = M37 ^ M38;
  mpc_XOR_u8(M37, M38, M43);
  // M44 = M39 ^ M40;
  mpc_XOR_u8(M39, M40, M44);
  // M45 = M42 ^ M41;
  mpc_XOR_u8(M42, M41, M45);
  // M46 = M44 & T6;
  mpc_AND_u8(M44, T6, M46, randomness, randCount, views, countY);
  // M47 = M40 & T8;
  mpc_AND_u8(M40, T8, M47, randomness, randCount, views, countY);
  // M48 = M39 & U7;
  mpc_AND_u8(M39, U7, M48, randomness, randCount, views, countY);
  // M49 = M43 & T16;
  mpc_AND_u8(M43, T16, M49, randomness, randCount, views, countY);
  // M50 = M38 & T9;
  mpc_AND_u8(M38, T9, M50, randomness, randCount, views, countY);
  // M51 = M37 & T17;
  mpc_AND_u8(M37, T17, M51, randomness, randCount, views, countY);
  // M52 = M42 & T15;
  mpc_AND_u8(M42, T15, M52, randomness, randCount, views, countY);
  // M53 = M45 & T27;
  mpc_AND_u8(M45, T27, M53, randomness, randCount, views, countY);
  // M54 = M41 & T10;
  mpc_AND_u8(M41, T10, M54, randomness, randCount, views, countY);
  // M55 = M44 & T13;
  mpc_AND_u8(M44, T13, M55, randomness, randCount, views, countY);
  // M56 = M40 & T23;
  mpc_AND_u8(M40, T23, M56, randomness, randCount, views, countY);
  // M57 = M39 & T19;
  mpc_AND_u8(M39, T19, M57, randomness, randCount, views, countY);
  // M58 = M43 & T3;
  mpc_AND_u8(M43, T3, M58, randomness, randCount, views, countY);
  // M59 = M38 & T22;
  mpc_AND_u8(M38, T22, M59, randomness, randCount, views, countY);
  // M60 = M37 & T20;
  mpc_AND_u8(M37, T20, M60, randomness, randCount, views, countY);
  // M61 = M42 & T1;
  mpc_AND_u8(M42, T1, M61, randomness, randCount, views, countY);
  // M62 = M45 & T4;
  mpc_AND_u8(M45, T4, M62, randomness, randCount, views, countY);
  // M63 = M41 & T2;
  mpc_AND_u8(M41, T2, M63, randomness, randCount, views, countY);

  // L0 = M61 ^ M62;
  mpc_XOR_u8(M61, M62, L0);
  // L1 = M50 ^ M56;
  mpc_XOR_u8(M50, M56, L1);
  // L2 = M46 ^ M48;
  mpc_XOR_u8(M46, M48, L2);
  // L3 = M47 ^ M55;
  mpc_XOR_u8(M47, M55, L3);
  // L4 = M54 ^ M58;
  mpc_XOR_u8(M54, M58, L4);
  // L5 = M49 ^ M61;
  mpc_XOR_u8(M49, M61, L5);
  // L6 = M62 ^ L5;
  mpc_XOR_u8(M62, L5, L6);
  // L7 = M46 ^ L3;
  mpc_XOR_u8(M46, L3, L7);
  // L8 = M51 ^ M59;
  mpc_XOR_u8(M51, M59, L8);
  // L9 = M52 ^ M53;
  mpc_XOR_u8(M52, M53, L9);
  // L10 = M53 ^ L4;
  mpc_XOR_u8(M53, L4, L10);
  // L11 = M60 ^ L2;
  mpc_XOR_u8(M60, L2, L11);
  // L12 = M48 ^ M51;
  mpc_XOR_u8(M48, M51, L12);
  // L13 = M50 ^ L0;
  mpc_XOR_u8(M50, L0, L13);
  // L14 = M52 ^ M61;
  mpc_XOR_u8(M52, M61, L14);
  // L15 = M55 ^ L1;
  mpc_XOR_u8(M55, L1, L15);
  // L16 = M56 ^ L0;
  mpc_XOR_u8(M56, L0, L16);
  // L17 = M57 ^ L1;
  mpc_XOR_u8(M57, L1, L17);
  // L18 = M58 ^ L8;
  mpc_XOR_u8(M58, L8, L18);
  // L19 = M63 ^ L4;
  mpc_XOR_u8(M63, L4, L19);
  // L20 = L0 ^ L1;
  mpc_XOR_u8(L0, L1, L20);

  // L21 = L1 ^ L7;
  mpc_XOR_u8(L1, L7, L21);
  // L22 = L3 ^ L12;
  mpc_XOR_u8(L3, L12, L22);
  // L23 = L18 ^ L2;
  mpc_XOR_u8(L18, L2, L23);
  // L24 = L15 ^ L9;
  mpc_XOR_u8(L15, L9, L24);
  // L25 = L6 ^ L10;
  mpc_XOR_u8(L6, L10, L25);
  // L26 = L7 ^ L9;
  mpc_XOR_u8(L7, L9, L26);
  // L27 = L8 ^ L10;
  mpc_XOR_u8(L8, L10, L27);
  // L28 = L11 ^ L14;
  mpc_XOR_u8(L11, L14, L28);
  // L29 = L11 ^ L17;
  mpc_XOR_u8(L11, L17, L29);

  // S0 = L6 ^ L24;
  mpc_XOR_u8(L6, L24, S0);

  // S1 = XNOR(L16 , L26);
  mpc_XNOR_u8(L16, L26, S1);

  // S2 = XNOR(L19 , L28);
  mpc_XNOR_u8(L19, L28, S2);

  // S3 = L6 ^ L21;
  mpc_XOR_u8(L6, L21, S3);
  // S4 = L20 ^ L22;
  mpc_XOR_u8(L20, L22, S4);
  // S5 = L25 ^ L29;
  mpc_XOR_u8(L25, L29, S5);

  // S6 = XNOR(L13 , L27);
  mpc_XNOR_u8(L13, L27, S6);

  // S7 = XNOR(L6 , L23);
  mpc_XNOR_u8(L6, L23, S7);
  // uint8_t res = (S0 << 7) | (S1 << 6) | (S2 << 5) | (S3 << 4) | (S4 << 3) |
  // (S5 << 2) | (S6 << 1) | (S7 << 0);
  mpc_LEFTSHIFT_u8(S0, 7, S0);
  mpc_LEFTSHIFT_u8(S1, 6, S1);
  mpc_LEFTSHIFT_u8(S2, 5, S2);
  mpc_LEFTSHIFT_u8(S3, 4, S3);
  mpc_LEFTSHIFT_u8(S4, 3, S4);
  mpc_LEFTSHIFT_u8(S5, 2, S5);
  mpc_LEFTSHIFT_u8(S6, 1, S6);
  mpc_LEFTSHIFT_u8(S7, 0, S7);

  mpc_OR_u8(S0, S1, state, randomness, randCount, views, countY);
  mpc_OR_u8(S2, state, state, randomness, randCount, views, countY);
  mpc_OR_u8(S3, state, state, randomness, randCount, views, countY);
  mpc_OR_u8(S4, state, state, randomness, randCount, views, countY);
  mpc_OR_u8(S5, state, state, randomness, randCount, views, countY);
  mpc_OR_u8(S6, state, state, randomness, randCount, views, countY);
  mpc_OR_u8(S7, state, state, randomness, randCount, views, countY);

  // printf("sbox gates %d\n", *countY -count_s);
  return 0;
}

void mpc_add_round_key(uint8_t state[][3], uint8_t w[][3], uint8_t r) {
  for (uint8_t i = 0; i < Nb; i++) {
    mpc_XOR_u8(state[Nb * 0 + i], w[4 * Nb * r + 4 * i + 0], state[Nb * 0 + i]);
    mpc_XOR_u8(state[Nb * 1 + i], w[4 * Nb * r + 4 * i + 1], state[Nb * 1 + i]);
    mpc_XOR_u8(state[Nb * 2 + i], w[4 * Nb * r + 4 * i + 2], state[Nb * 2 + i]);
    mpc_XOR_u8(state[Nb * 3 + i], w[4 * Nb * r + 4 * i + 3], state[Nb * 3 + i]);
  }
}

void mpc_mix_columns(uint8_t state[][3], unsigned char *randomness[3],
                     int *randCount, View views[3], int *countY) {
  uint8_t col[4][3];
  clear_array(4, 3, col);

  for (int j = 0; j < Nb; j++) {
    for (int i = 0; i < 4; i++) {
      for (int k = 0; k < 3; k++) {
        col[i][k] = state[Nb * i + j][k];
      }
    }

    uint8_t a[4][3];
    uint8_t b[4][3];
    uint8_t h[3];
    uint8_t no = 0x1B;
    clear_array(4, 3, a);
    clear_array(4, 3, b);
    bzero(h, 3);

    for (int c = 0; c < 4; c++) {
      uint8_t t[3];

      // a[c] = col[c];
      memcpy(a[c], col[c], 3);
      // h = (uint8_t)((signed char)col[c] >> 7);

      h[0] = (uint8_t)((signed char)col[c][0] >> 7);
      h[1] = (uint8_t)((signed char)col[c][1] >> 7);
      h[2] = (uint8_t)((signed char)col[c][2] >> 7);
      // b[c] = col[c] << 1;
      mpc_LEFTSHIFT_u8(col[c], 1, b[c]);
      // b[c] ^= 0x1B & h; ==
      // t = 0x1B & h; b[c] = b[c] ^ t
      mpc_ANDK_u8(h, no, t, randomness, randCount, views, countY);
      mpc_XOR_u8(b[c], t, b[c]);
    }

    uint8_t t0[3];

    // col[0] = b[0] ^ a[3] ^ a[2] ^ b[1] ^ a[1]; /* 2 * a0 + a3 + a2 + 3 * a1
    // */
    mpc_XOR_u8(b[0], a[3], t0);
    mpc_XOR_u8(t0, a[2], t0);
    mpc_XOR_u8(t0, b[1], t0);
    mpc_XOR_u8(t0, a[1], col[0]);

    // col[1] = b[1] ^ a[0] ^ a[3] ^ b[2] ^ a[2]; /* 2 * a1 + a0 + a3 + 3 * a2
    // */
    mpc_XOR_u8(b[1], a[0], t0);
    mpc_XOR_u8(t0, a[3], t0);
    mpc_XOR_u8(t0, b[2], t0);
    mpc_XOR_u8(t0, a[2], col[1]);

    // col[2] = b[2] ^ a[1] ^ a[0] ^ b[3] ^ a[3]; /* 2 * a2 + a1 + a0 + 3 * a3
    // */
    mpc_XOR_u8(b[2], a[1], t0);
    mpc_XOR_u8(t0, a[0], t0);
    mpc_XOR_u8(t0, b[3], t0);
    mpc_XOR_u8(t0, a[3], col[2]);

    // col[3] = b[3] ^ a[2] ^ a[1] ^ b[0] ^ a[0]; /* 2 * a3 + a2 + a1 + 3 * a0
    // */
    mpc_XOR_u8(b[3], a[2], t0);
    mpc_XOR_u8(t0, a[1], t0);
    mpc_XOR_u8(t0, b[0], t0);
    mpc_XOR_u8(t0, a[0], col[3]);

    for (int i = 0; i < 4; i++) {
      for (int k = 0; k < 3; k++) {
        state[Nb * i + j][k] = col[i][k];
      }
    }
  }
}

void mpc_shift_rows(uint8_t state[][3]) {
  uint8_t i, j, k, s, tmp;

  for (i = 1; i < 4; i++) {
    s = 0;
    while (s < i) {
      for (j = 0; j < 3; j++) {
        tmp = state[Nb * i + 0][j];
        for (k = 1; k < Nb; k++) {
          state[Nb * i + k - 1][j] = state[Nb * i + k][j];
        }
        state[Nb * i + Nb - 1][j] = tmp;
      }
      s++;
    }
  }
}

void mpc_sub_bytes(uint8_t state[][3], unsigned char *randomness[3],
                   int *randCount, View views[3], int *countY) {
  uint8_t i, j;
  // uint8_t t0[2] = {0xf0, 0xf0};
  // uint8_t t1[2] = {0x0f, 0x0f};

  uint8_t t0 = 0xf0;
  uint8_t t1 = 0x0f;

  for (i = 0; i < 4; i++) {
    for (j = 0; j < Nb; j++) {
      uint8_t buf[3];
      uint8_t row[3];
      uint8_t col[3];
      uint8_t index[3];

      bzero(buf, 3);
      bzero(row, 3);
      bzero(col, 3);
      bzero(index, 3);

      mpc_ANDK_u8(state[Nb * i + j], t0, row, randomness, randCount, views,
                  countY);
      mpc_ANDK_u8(state[Nb * i + j], t1, col, randomness, randCount, views,
                  countY);

      mpc_ADD_u8(row, col, index, randomness, randCount, views, countY);
      mpc_small_sbox(state[Nb * i + j], index, randomness, randCount, views,
                     countY);
    }
  }
}

int aes(unsigned char *results[3], unsigned char *inputs[3], int numBytes,
        unsigned char *randomness[3], int *randCount, View views[3],
        int *countY) {
  int msg_len = numBytes - 16 - Nb * (Nr + 1) * 4;

  if (msg_len % 16 != 0) {
    printf("Input not paddded (msg_size: %d)\n", msg_len);
    exit(0);
  }

  uint8_t padding_len = 16 - (msg_len - 1) % 16 - 1; // 0
  int block_no = (padding_len + msg_len) / AES_BLOCK_SIZE;

  printf("Block num: %d, Padding len: %d\n", block_no, padding_len);

  msg_len = msg_len + padding_len;

  // prepare inputs
  uint8_t w[Nb * (Nr + 1) * 4][3];
  uint8_t iv[AES_BLOCK_SIZE][3];
  uint8_t msg[msg_len][3];

  clear_array(AES_BLOCK_SIZE, 3, iv);
  clear_array(msg_len, 3, msg);
  clear_array(Nb * (Nr + 1) * 4, 3, w);

  for (int i = 0; i < AES_BLOCK_SIZE; i++) {
    for (int j = 0; j < 3; j++) {
      iv[i][j] = inputs[j][i];
    }
  }

  for (int i = 0; i < Nb * (Nr + 1) * 4; i++) {
    for (int j = 0; j < 3; j++) {
      w[i][j] = inputs[j][i + 16];
    }
  }

  for (int i = 0; i < msg_len; i++) {
    for (int j = 0; j < 3; j++) {
      if (i < msg_len - padding_len) {
        msg[i][j] = inputs[j][i + 16 + 176];
      } else {
        printf("Shouldn't reach here!!");
        msg[i][j] = 0;
      }
    }
  }

  // printf("Input: ");
	// for (int i = 0; i < msg_len; i++) {
	// 	printf("%02X", msg[i][0] ^ msg[i][1] ^ msg[i][2]);
	// }
	// printf("\n");

  for (int blk = 0; blk < block_no; blk++) {
    clock_t t_begin = clock();
    int count_s = *countY;

    uint8_t state[4 * Nb][3];
    clear_array(4 * Nb, 3, state);

    for (int m = 0; m < 4; m++) {
      for (int n = 0; n < Nb; n++) {
        for (int i = 0; i < 3; i++) {
          state[Nb * m + n][i] = msg[m + 4 * n + blk * AES_BLOCK_SIZE][i];
          if (blk == 0) {
            state[Nb * m + n][i] ^= iv[m + 4 * n][i];
            // mpc_XOR_u8(state[Nb * m + n][i], iv[ m + 4 * n][i], state[Nb * m
            // + n][i]);
          } else {
            state[Nb * m + n][i] ^=
                results[i][m + 4 * n + (blk - 1) * AES_BLOCK_SIZE];
            // mpc_XOR_u8(state[Nb * m + n][i], results[i][m + 4 * n + (blk - 1)
            // * AES_BLOCK_SIZE], state[Nb * m + n][i]);
          }
        }
      }
    }

    // aes encryptioin
    mpc_add_round_key(state, w, 0);

    for (int r = 1; r < Nr; r++) {
      mpc_sub_bytes(state, randomness, randCount, views, countY);
      mpc_shift_rows(state);
      mpc_mix_columns(state, randomness, randCount, views, countY);
      mpc_add_round_key(state, w, r);
    }
    mpc_sub_bytes(state, randomness, randCount, views, countY);
    mpc_shift_rows(state);
    mpc_add_round_key(state, w, Nr);

    // copy results
    for (int m = 0; m < 4; m++) {
      for (int n = 0; n < Nb; n++) {
        for (int i = 0; i < 3; i++) {
          results[i][m + 4 * n + blk * AES_BLOCK_SIZE] = state[Nb * m + n][i];
        }
      }
    }
    // printf("aes 1 block time %ju us\n", (uintmax_t)(clock() - t_begin) * 1000
    // * 1000/ CLOCKS_PER_SEC); printf("aes 1 block gates %d\n", *countY -
    // count_s);
  }
  // printf("Cipher: ");
	// for (int i = 0; i < msg_len; i++) {
	// 	printf("%02X", results[0][i] ^ results[1][i] ^ results[2][i]);
	// }
	// printf("\n");

  return 0;
}

a commit(int numBytes, unsigned char *shares[3], unsigned char *randomness[3],
         unsigned char rs[3][4], View views[3]) {
  uint8_t *inputs[3];
  inputs[0] = shares[0];
  inputs[1] = shares[1];
  inputs[2] = shares[2];

  uint8_t *cipher[3];
  uint8_t *result[3];

  for (int i = 0; i < 3; i++) {
    cipher[i] = calloc(CIPHER_LEN, sizeof(uint8_t));
    result[i] = calloc(OUTPUT_LEN, sizeof(uint8_t));
  }

  int *countY = calloc(1, sizeof(int));
  int *randCount = calloc(1, sizeof(int));

  memcpy(views[0].x, inputs[0], numBytes);
  memcpy(views[1].x, inputs[1], numBytes);
  memcpy(views[2].x, inputs[2], numBytes);

  aes(cipher, inputs, numBytes, randomness, randCount, views, countY);

  // add output to the view
  memcpy(&views[0].y[*countY], cipher[0], CIPHER_LEN);
  memcpy(&views[1].y[*countY], cipher[1], CIPHER_LEN);
  memcpy(&views[2].y[*countY], cipher[2], CIPHER_LEN);
  *countY += CIPHER_LEN / 4;

  // make input public by outputting it.
  memcpy(&views[0].y[*countY], inputs[0] + IV_LEN + AES_EXPANDED_KEYS_LEN, INPUT_LEN);
  memcpy(&views[1].y[*countY], inputs[1] + IV_LEN + AES_EXPANDED_KEYS_LEN, INPUT_LEN);
  memcpy(&views[2].y[*countY], inputs[2] + IV_LEN + AES_EXPANDED_KEYS_LEN, INPUT_LEN);
  *countY += INPUT_LEN / 4;

  printf("Number of gates: %d\n", *countY);
  printf("Number of randomness: %d\n", *randCount);

  a a;
  for (int i = 0; i < 3; i++) {
    output_var(views[i], result[i], OUTPUT_LEN);
    memcpy(a.yp[i], result[i], OUTPUT_LEN);
  }

  // Printing output
  printf("Ciphertext: ");
	for (int i = 0; i < CIPHER_LEN; i++) {
		printf("%02X", result[0][i] ^ result[1][i] ^ result[2][i]);
	}
	printf("\n");

  printf("Plaintext: ");
	for (int i = CIPHER_LEN; i < OUTPUT_LEN; i++) {
		printf("%02X", result[0][i] ^ result[1][i] ^ result[2][i]);
	}
	printf("\n");

  free_array(3, result);
  free_array(3, cipher);
  free(countY);
  free(randCount);

  return a;
}

z prove(int e, unsigned char keys[3][16], unsigned char rs[3][4],
        View views[3]) {
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
 * AES-CBC
 * 
 * Key: B6F1380942BD9401339F7F6F09353730
 * IV: 9C7BF0CC70BA60E4FA2C6ADE205DD8FB
 * Plaintext: B66643139446DE482E576B18D489865D5D5B261617A1699A130A766ED837B92E0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F
 * Expected Ciphertext: 94077910BC7D907CD1F68EAC01C75FB7EE0FE2D3D60FA0D8698CEF95FE9F31333690FF603CB7B0BED38DE5894E809E75
***/

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

  int input_len = IV_LEN + AES_EXPANDED_KEYS_LEN + INPUT_LEN;

  printf("String length: %d\n", INPUT_LEN);
  printf("Iterations of SHA: %d\n", NUM_ROUNDS);

  uint8_t input[input_len];
  memset(input, 0, input_len);

  // Nb * (Nr + 1) * 4 = 176
  uint8_t ex_keys[AES_EXPANDED_KEYS_LEN];

  // key expansion
  key_expansion(AES_KEY, ex_keys);

  memcpy(input, IV, IV_LEN);
  memcpy(input + IV_LEN, ex_keys, AES_EXPANDED_KEYS_LEN);
  memcpy(input + IV_LEN + AES_EXPANDED_KEYS_LEN, USERNAME, INPUT_LEN);

	printf("AES KEY: ");
	for (int i = 0; i < 16; i++) {
		printf("%02X", AES_KEY[i]);
	}
	printf("\n");

	printf("IV: ");
	for (int i = 0; i < 16; i++) {
		printf("%02X", IV[i]);
	}
	printf("\n");

	printf("Input: ");
	for (int i = 0; i < INPUT_LEN; i++) {
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
  }

  free_array(3, randomness);
  // Generating E
  uint8_t finalOutput[OUTPUT_LEN];
  for (int i = 0; i < OUTPUT_LEN; i++) {
    finalOutput[i] = as[0].yp[0][i] ^ as[0].yp[1][i] ^ as[0].yp[2][i];
  }
  H3(finalOutput, as, NUM_ROUNDS, es);

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