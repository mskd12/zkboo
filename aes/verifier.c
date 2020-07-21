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

int mpc_small_sbox(uint8_t state[2], uint8_t n[2], View* pve, View* pve1,
                   unsigned char* randomness[2], int* randCount, int* countY) {
  uint8_t U0[2], U1[2], U2[2], U3[2], U4[2], U5[2], U6[2], U7[2];
  uint8_t T1[2], T2[2], T3[2], T4[2], T5[2], T6[2], T7[2], T8[2];
  uint8_t T9[2], T10[2], T11[2], T12[2], T13[2], T14[2], T15[2], T16[2];
  uint8_t T17[2], T18[2], T19[2], T20[2], T21[2], T22[2], T23[2], T24[2];
  uint8_t T25[2], T26[2], T27[2];
  uint8_t M1[2], M2[2], M3[2], M4[2], M5[2], M6[2], M7[2], M8[2];
  uint8_t M9[2], M10[2], M11[2], M12[2], M13[2], M14[2], M15[2], M16[2];
  uint8_t M17[2], M18[2], M19[2], M20[2], M21[2], M22[2], M23[2], M24[2];
  uint8_t M25[2], M26[2], M27[2], M28[2], M29[2], M30[2], M31[2], M32[2];
  uint8_t M33[2], M34[2], M35[2], M36[2], M37[2], M38[2], M39[2], M40[2];
  uint8_t M41[2], M42[2], M43[2], M44[2], M45[2], M46[2], M47[2], M48[2];
  uint8_t M49[2], M50[2], M51[2], M52[2], M53[2], M54[2], M55[2], M56[2];
  uint8_t M57[2], M58[2], M59[2], M60[2], M61[2], M62[2], M63[2];
  uint8_t L0[2], L1[2], L2[2], L3[2], L4[2], L5[2], L6[2], L7[2];
  uint8_t L8[2], L9[2], L10[2], L11[2], L12[2], L13[2], L14[2], L15[2];
  uint8_t L16[2], L17[2], L18[2], L19[2], L20[2], L21[2], L22[2], L23[2];
  uint8_t L24[2], L25[2], L26[2], L27[2], L28[2], L29[2];
  uint8_t S0[2], S1[2], S2[2], S3[2], S4[2], S5[2], S6[2], S7[2];

  uint8_t buf[2];

  // View* pve = &pve;
  // View* pve1 = &pve1;

  // U0 = (n & ( 1 << 7 )) >> 7;
  if (mpc_ANDK_verify_u8(n, (uint8_t)(1 << 7), buf, pve, pve1, randomness,
                         randCount, countY) == FAIL)
    error_handler(__LINE__, "ANDK");
  mpc_RIGHTSHIFT2_u8(buf, 7, U0);
  // U1 = (n & ( 1 << 6 )) >> 6;
  if (mpc_ANDK_verify_u8(n, (uint8_t)(1 << 6), buf, pve, pve1, randomness,
                         randCount, countY) == FAIL)
    error_handler(__LINE__, "ANDK");

  mpc_RIGHTSHIFT2_u8(buf, 6, U1);
  // U2 = (n & ( 1 << 5 )) >> 5;
  if (mpc_ANDK_verify_u8(n, (uint8_t)(1 << 5), buf, pve, pve1, randomness,
                         randCount, countY) == FAIL)
    error_handler(__LINE__, "ANDK");

  mpc_RIGHTSHIFT2_u8(buf, 5, U2);
  // U3 = (n & ( 1 << 4 )) >> 4;
  if (mpc_ANDK_verify_u8(n, (uint8_t)(1 << 4), buf, pve, pve1, randomness,
                         randCount, countY) == FAIL)
    error_handler(__LINE__, "ANDK");

  mpc_RIGHTSHIFT2_u8(buf, 4, U3);
  // U4 = (n & ( 1 << 3 )) >> 3;
  if (mpc_ANDK_verify_u8(n, (uint8_t)(1 << 3), buf, pve, pve1, randomness,
                         randCount, countY) == FAIL)
    error_handler(__LINE__, "ANDK");

  mpc_RIGHTSHIFT2_u8(buf, 3, U4);
  // U5 = (n & ( 1 << 2 )) >> 2;
  if (mpc_ANDK_verify_u8(n, (uint8_t)(1 << 2), buf, pve, pve1, randomness,
                         randCount, countY) == FAIL)
    error_handler(__LINE__, "ANDK");
  mpc_RIGHTSHIFT2_u8(buf, 2, U5);
  // U6 = (n & ( 1 << 1 )) >> 1;
  if (mpc_ANDK_verify_u8(n, (uint8_t)(1 << 1), buf, pve, pve1, randomness,
                         randCount, countY) == FAIL)
    error_handler(__LINE__, "ANDK");
  mpc_RIGHTSHIFT2_u8(buf, 1, U6);
  // U7 = (n & ( 1 << 0 )) >> 0;
  if (mpc_ANDK_verify_u8(n, (uint8_t)(1 << 0), buf, pve, pve1, randomness,
                         randCount, countY) == FAIL)
    error_handler(__LINE__, "ANDK");
  mpc_RIGHTSHIFT2_u8(buf, 0, U7);

  // T1 = U0 ^ U3;
  mpc_XOR2_u8(U0, U3, T1);
  // T2 = U0 ^ U5;
  mpc_XOR2_u8(U0, U5, T2);
  // T3 = U0 ^ U6;
  mpc_XOR2_u8(U0, U6, T3);
  // T4 = U3 ^ U5;
  mpc_XOR2_u8(U3, U5, T4);
  // T5 = U4 ^ U6;
  mpc_XOR2_u8(U4, U6, T5);
  // T6 = T1 ^ T5;
  mpc_XOR2_u8(T1, T5, T6);
  // T7 = U1 ^ U2;
  mpc_XOR2_u8(U1, U2, T7);
  // T8 = U7 ^ T6;
  mpc_XOR2_u8(U7, T6, T8);
  // T9 = U7 ^ T7;
  mpc_XOR2_u8(U7, T7, T9);
  // T10 = T6 ^ T7;
  mpc_XOR2_u8(T6, T7, T10);
  // T11 = U1 ^ U5;
  mpc_XOR2_u8(U1, U5, T11);
  // T12 = U2 ^ U5;
  mpc_XOR2_u8(U2, U5, T12);
  // T13 = T3 ^ T4;
  mpc_XOR2_u8(T3, T4, T13);
  // T14 = T6 ^ T11;
  mpc_XOR2_u8(T6, T11, T14);
  // T15 = T5 ^ T11;
  mpc_XOR2_u8(T5, T11, T15);
  // T16 = T5 ^ T12;
  mpc_XOR2_u8(T5, T12, T16);
  // T17 = T9 ^ T16;
  mpc_XOR2_u8(T9, T16, T17);
  // T18 = U3 ^ U7;
  mpc_XOR2_u8(U3, U7, T18);
  // T19 = T7 ^ T18;
  mpc_XOR2_u8(T7, T18, T19);
  // T20 = T1 ^ T19;
  mpc_XOR2_u8(T1, T19, T20);
  // T21 = U6 ^ U7;
  mpc_XOR2_u8(U6, U7, T21);
  // T22 = T7 ^ T21;
  mpc_XOR2_u8(T7, T21, T22);
  // T23 = T2 ^ T22;
  mpc_XOR2_u8(T2, T22, T23);
  // T24 = T2 ^ T10;
  mpc_XOR2_u8(T2, T10, T24);
  // T25 = T20 ^ T17;
  mpc_XOR2_u8(T20, T17, T25);
  // T26 = T3 ^ T16;
  mpc_XOR2_u8(T3, T16, T26);
  // T27 = T1 ^ T12;
  mpc_XOR2_u8(T1, T12, T27);

  // M1 = T13 & T6;
  if (mpc_AND_verify_u8(T13, T6, M1, pve, pve1, randomness, randCount,
                        countY) == FAIL)
    error_handler(__LINE__, "AND");
  // M2 = T23 & T8;
  if (mpc_AND_verify_u8(T23, T8, M2, pve, pve1, randomness, randCount,
                        countY) == FAIL)
    error_handler(__LINE__, "AND");

  // M3 = T14 ^ M1;
  mpc_XOR2_u8(T14, M1, M3);
  // M4 = T19 & U7;
  if (mpc_AND_verify_u8(T19, U7, M4, pve, pve1, randomness, randCount,
                        countY) == FAIL)
    error_handler(__LINE__, "AND");
  // M5 = M4 ^ M1;
  mpc_XOR2_u8(M4, M1, M5);
  // M6 = T3 & T16;
  if (mpc_AND_verify_u8(T3, T16, M6, pve, pve1, randomness, randCount,
                        countY) == FAIL)
    error_handler(__LINE__, "AND");
  // M7 = T22 & T9;
  if (mpc_AND_verify_u8(T22, T9, M7, pve, pve1, randomness, randCount,
                        countY) == FAIL)
    error_handler(__LINE__, "AND");
  // M8 = T26 ^ M6;
  mpc_XOR2_u8(T26, M6, M8);
  // M9 = T20 & T17;
  if (mpc_AND_verify_u8(T20, T17, M9, pve, pve1, randomness, randCount,
                        countY) == FAIL)
    error_handler(__LINE__, "AND");
  // M10 = M9 ^ M6;
  mpc_XOR2_u8(M9, M6, M10);
  // M11 = T1 & T15;
  if (mpc_AND_verify_u8(T1, T15, M11, pve, pve1, randomness, randCount,
                        countY) == FAIL)
    error_handler(__LINE__, "AND");
  // M12 = T4 & T27;
  if (mpc_AND_verify_u8(T4, T27, M12, pve, pve1, randomness, randCount,
                        countY) == FAIL)
    error_handler(__LINE__, "AND");
  // M13 = M12 ^ M11;
  mpc_XOR2_u8(M12, M11, M13);
  // M14 = T2 & T10;
  if (mpc_AND_verify_u8(T2, T10, M14, pve, pve1, randomness, randCount,
                        countY) == FAIL)
    error_handler(__LINE__, "AND");
  // M15 = M14 ^ M11;
  mpc_XOR2_u8(M14, M11, M15);
  // M16 = M3 ^ M2;
  mpc_XOR2_u8(M3, M2, M16);
  // M17 = M5 ^ T24;
  mpc_XOR2_u8(M5, T24, M17);
  // M18 = M8 ^ M7;
  mpc_XOR2_u8(M8, M7, M18);
  // M19 = M10 ^ M15;
  mpc_XOR2_u8(M10, M15, M19);
  // M20 = M16 ^ M13;
  mpc_XOR2_u8(M16, M13, M20);

  // M21 = M17 ^ M15;
  mpc_XOR2_u8(M17, M15, M21);
  // M22 = M18 ^ M13;
  mpc_XOR2_u8(M18, M13, M22);
  // M23 = M19 ^ T25;
  mpc_XOR2_u8(M19, T25, M23);
  // M24 = M22 ^ M23;
  mpc_XOR2_u8(M22, M23, M24);
  // M25 = M22 & M20;
  if (mpc_AND_verify_u8(M22, M20, M25, pve, pve1, randomness, randCount,
                        countY) == FAIL)
    error_handler(__LINE__, "AND");
  // M26 = M21 ^ M25;
  mpc_XOR2_u8(M21, M25, M26);
  // M27 = M20 ^ M21;
  mpc_XOR2_u8(M20, M21, M27);
  // M28 = M23 ^ M25;
  mpc_XOR2_u8(M23, M25, M28);
  // M29 = M28 & M27;
  if (mpc_AND_verify_u8(M28, M27, M29, pve, pve1, randomness, randCount,
                        countY) == FAIL)
    error_handler(__LINE__, "AND");
  // M30 = M26 & M24;
  if (mpc_AND_verify_u8(M26, M24, M30, pve, pve1, randomness, randCount,
                        countY) == FAIL)
    error_handler(__LINE__, "AND");
  // M31 = M20 & M23;
  if (mpc_AND_verify_u8(M20, M23, M31, pve, pve1, randomness, randCount,
                        countY) == FAIL)
    error_handler(__LINE__, "AND");
  // M32 = M27 & M31;
  if (mpc_AND_verify_u8(M27, M31, M32, pve, pve1, randomness, randCount,
                        countY) == FAIL)
    error_handler(__LINE__, "AND");
  // M33 = M27 ^ M25;
  mpc_XOR2_u8(M27, M25, M33);
  // M34 = M21 & M22;
  if (mpc_AND_verify_u8(M21, M22, M34, pve, pve1, randomness, randCount,
                        countY) == FAIL)
    error_handler(__LINE__, "AND");
  // M35 = M24 & M34;
  if (mpc_AND_verify_u8(M24, M34, M35, pve, pve1, randomness, randCount,
                        countY) == FAIL)
    error_handler(__LINE__, "AND");
  // M36 = M24 ^ M25;
  mpc_XOR2_u8(M24, M25, M36);
  // M37 = M21 ^ M29;
  mpc_XOR2_u8(M21, M29, M37);
  // M38 = M32 ^ M33;
  mpc_XOR2_u8(M32, M33, M38);
  // M39 = M23 ^ M30;
  mpc_XOR2_u8(M23, M30, M39);
  // M40 = M35 ^ M36;
  mpc_XOR2_u8(M35, M36, M40);
  // M41 = M38 ^ M40;
  mpc_XOR2_u8(M38, M40, M41);
  // M42 = M37 ^ M39;
  mpc_XOR2_u8(M37, M39, M42);
  // M43 = M37 ^ M38;
  mpc_XOR2_u8(M37, M38, M43);
  // M44 = M39 ^ M40;
  mpc_XOR2_u8(M39, M40, M44);
  // M45 = M42 ^ M41;
  mpc_XOR2_u8(M42, M41, M45);
  // M46 = M44 & T6;
  if (mpc_AND_verify_u8(M44, T6, M46, pve, pve1, randomness, randCount,
                        countY) == FAIL)
    error_handler(__LINE__, "AND");
  // M47 = M40 & T8;
  if (mpc_AND_verify_u8(M40, T8, M47, pve, pve1, randomness, randCount,
                        countY) == FAIL)
    error_handler(__LINE__, "AND");
  // M48 = M39 & U7;
  if (mpc_AND_verify_u8(M39, U7, M48, pve, pve1, randomness, randCount,
                        countY) == FAIL)
    error_handler(__LINE__, "AND");
  // M49 = M43 & T16;
  if (mpc_AND_verify_u8(M43, T16, M49, pve, pve1, randomness, randCount,
                        countY) == FAIL)
    error_handler(__LINE__, "AND");
  // M50 = M38 & T9;
  if (mpc_AND_verify_u8(M38, T9, M50, pve, pve1, randomness, randCount,
                        countY) == FAIL)
    error_handler(__LINE__, "AND");
  // M51 = M37 & T17;
  if (mpc_AND_verify_u8(M37, T17, M51, pve, pve1, randomness, randCount,
                        countY) == FAIL)
    error_handler(__LINE__, "AND");
  // M52 = M42 & T15;
  if (mpc_AND_verify_u8(M42, T15, M52, pve, pve1, randomness, randCount,
                        countY) == FAIL)
    error_handler(__LINE__, "AND");
  // M53 = M45 & T27;
  if (mpc_AND_verify_u8(M45, T27, M53, pve, pve1, randomness, randCount,
                        countY) == FAIL)
    error_handler(__LINE__, "AND");
  // M54 = M41 & T10;
  if (mpc_AND_verify_u8(M41, T10, M54, pve, pve1, randomness, randCount,
                        countY) == FAIL)
    error_handler(__LINE__, "AND");
  // M55 = M44 & T13;
  if (mpc_AND_verify_u8(M44, T13, M55, pve, pve1, randomness, randCount,
                        countY) == FAIL)
    error_handler(__LINE__, "AND");
  // M56 = M40 & T23;
  if (mpc_AND_verify_u8(M40, T23, M56, pve, pve1, randomness, randCount,
                        countY) == FAIL)
    error_handler(__LINE__, "AND");
  // M57 = M39 & T19;
  if (mpc_AND_verify_u8(M39, T19, M57, pve, pve1, randomness, randCount,
                        countY) == FAIL)
    error_handler(__LINE__, "AND");
  // M58 = M43 & T3;
  if (mpc_AND_verify_u8(M43, T3, M58, pve, pve1, randomness, randCount,
                        countY) == FAIL)
    error_handler(__LINE__, "AND");
  // M59 = M38 & T22;
  if (mpc_AND_verify_u8(M38, T22, M59, pve, pve1, randomness, randCount,
                        countY) == FAIL)
    error_handler(__LINE__, "AND");
  // M60 = M37 & T20;
  if (mpc_AND_verify_u8(M37, T20, M60, pve, pve1, randomness, randCount,
                        countY) == FAIL)
    error_handler(__LINE__, "AND");
  // M61 = M42 & T1;
  if (mpc_AND_verify_u8(M42, T1, M61, pve, pve1, randomness, randCount,
                        countY) == FAIL)
    error_handler(__LINE__, "AND");
  // M62 = M45 & T4;
  if (mpc_AND_verify_u8(M45, T4, M62, pve, pve1, randomness, randCount,
                        countY) == FAIL)
    error_handler(__LINE__, "AND");
  // M63 = M41 & T2;
  if (mpc_AND_verify_u8(M41, T2, M63, pve, pve1, randomness, randCount,
                        countY) == FAIL)
    error_handler(__LINE__, "AND");

  // L0 = M61 ^ M62;
  mpc_XOR2_u8(M61, M62, L0);
  // L1 = M50 ^ M56;
  mpc_XOR2_u8(M50, M56, L1);
  // L2 = M46 ^ M48;
  mpc_XOR2_u8(M46, M48, L2);
  // L3 = M47 ^ M55;
  mpc_XOR2_u8(M47, M55, L3);
  // L4 = M54 ^ M58;
  mpc_XOR2_u8(M54, M58, L4);
  // L5 = M49 ^ M61;
  mpc_XOR2_u8(M49, M61, L5);
  // L6 = M62 ^ L5;
  mpc_XOR2_u8(M62, L5, L6);
  // L7 = M46 ^ L3;
  mpc_XOR2_u8(M46, L3, L7);
  // L8 = M51 ^ M59;
  mpc_XOR2_u8(M51, M59, L8);
  // L9 = M52 ^ M53;
  mpc_XOR2_u8(M52, M53, L9);
  // L10 = M53 ^ L4;
  mpc_XOR2_u8(M53, L4, L10);
  // L11 = M60 ^ L2;
  mpc_XOR2_u8(M60, L2, L11);
  // L12 = M48 ^ M51;
  mpc_XOR2_u8(M48, M51, L12);
  // L13 = M50 ^ L0;
  mpc_XOR2_u8(M50, L0, L13);
  // L14 = M52 ^ M61;
  mpc_XOR2_u8(M52, M61, L14);
  // L15 = M55 ^ L1;
  mpc_XOR2_u8(M55, L1, L15);
  // L16 = M56 ^ L0;
  mpc_XOR2_u8(M56, L0, L16);
  // L17 = M57 ^ L1;
  mpc_XOR2_u8(M57, L1, L17);
  // L18 = M58 ^ L8;
  mpc_XOR2_u8(M58, L8, L18);
  // L19 = M63 ^ L4;
  mpc_XOR2_u8(M63, L4, L19);
  // L20 = L0 ^ L1;
  mpc_XOR2_u8(L0, L1, L20);

  // L21 = L1 ^ L7;
  mpc_XOR2_u8(L1, L7, L21);
  // L22 = L3 ^ L12;
  mpc_XOR2_u8(L3, L12, L22);
  // L23 = L18 ^ L2;
  mpc_XOR2_u8(L18, L2, L23);
  // L24 = L15 ^ L9;
  mpc_XOR2_u8(L15, L9, L24);
  // L25 = L6 ^ L10;
  mpc_XOR2_u8(L6, L10, L25);
  // L26 = L7 ^ L9;
  mpc_XOR2_u8(L7, L9, L26);
  // L27 = L8 ^ L10;
  mpc_XOR2_u8(L8, L10, L27);
  // L28 = L11 ^ L14;
  mpc_XOR2_u8(L11, L14, L28);
  // L29 = L11 ^ L17;
  mpc_XOR2_u8(L11, L17, L29);

  // S0 = L6 ^ L24;
  mpc_XOR2_u8(L6, L24, S0);

  // S1 = XNOR(L16 , L26);
  mpc_XNOR2_u8(L16, L26, S1);

  // S2 = XNOR(L19 , L28);
  mpc_XNOR2_u8(L19, L28, S2);

  // S3 = L6 ^ L21;
  mpc_XOR2_u8(L6, L21, S3);
  // S4 = L20 ^ L22;
  mpc_XOR2_u8(L20, L22, S4);
  // S5 = L25 ^ L29;
  mpc_XOR2_u8(L25, L29, S5);

  // S6 = XNOR(L13 , L27);
  mpc_XNOR2_u8(L13, L27, S6);

  // S7 = XNOR(L6 , L23);
  mpc_XNOR2_u8(L6, L23, S7);
  // uint8_t res = (S0 << 7) | (S1 << 6) | (S2 << 5) | (S3 << 4) | (S4 << 3) |
  // (S5 << 2) | (S6 << 1) | (S7 << 0);
  mpc_LEFTSHIFT2_u8(S0, 7, S0);
  mpc_LEFTSHIFT2_u8(S1, 6, S1);
  mpc_LEFTSHIFT2_u8(S2, 5, S2);
  mpc_LEFTSHIFT2_u8(S3, 4, S3);
  mpc_LEFTSHIFT2_u8(S4, 3, S4);
  mpc_LEFTSHIFT2_u8(S5, 2, S5);
  mpc_LEFTSHIFT2_u8(S6, 1, S6);
  mpc_LEFTSHIFT2_u8(S7, 0, S7);

  if (mpc_OR_verify_u8(S0, S1, state, pve, pve1, randomness, randCount,
                       countY) == FAIL)
    error_handler(__LINE__, "OR");
  if (mpc_OR_verify_u8(S2, state, state, pve, pve1, randomness, randCount,
                       countY) == FAIL)
    error_handler(__LINE__, "OR");
  if (mpc_OR_verify_u8(S3, state, state, pve, pve1, randomness, randCount,
                       countY) == FAIL)
    error_handler(__LINE__, "OR");
  if (mpc_OR_verify_u8(S4, state, state, pve, pve1, randomness, randCount,
                       countY) == FAIL)
    error_handler(__LINE__, "OR");
  if (mpc_OR_verify_u8(S5, state, state, pve, pve1, randomness, randCount,
                       countY) == FAIL)
    error_handler(__LINE__, "OR");
  if (mpc_OR_verify_u8(S6, state, state, pve, pve1, randomness, randCount,
                       countY) == FAIL)
    error_handler(__LINE__, "OR");
  if (mpc_OR_verify_u8(S7, state, state, pve, pve1, randomness, randCount,
                       countY) == FAIL)
    error_handler(__LINE__, "OR");

  return 0;
}

void mpc_add_round_key(uint8_t state[][2], uint8_t w[][2], uint8_t r) {
  for (uint8_t i = 0; i < Nb; i++) {
    mpc_XOR2_u8(state[Nb * 0 + i], w[4 * Nb * r + 4 * i + 0],
                state[Nb * 0 + i]);
    mpc_XOR2_u8(state[Nb * 1 + i], w[4 * Nb * r + 4 * i + 1],
                state[Nb * 1 + i]);
    mpc_XOR2_u8(state[Nb * 2 + i], w[4 * Nb * r + 4 * i + 2],
                state[Nb * 2 + i]);
    mpc_XOR2_u8(state[Nb * 3 + i], w[4 * Nb * r + 4 * i + 3],
                state[Nb * 3 + i]);
  }
}

int mpc_mix_columns(uint8_t state[][2], View* pve, View* pve1,
                    unsigned char* randomness[2], int* randCount, int* countY) {
  uint8_t col[4][2];
  clear_array(4, 2, col);

  // View* pve = &z.ve;
  // View* pve1 = &z.ve1;

  for (int j = 0; j < Nb; j++) {
    for (int i = 0; i < 4; i++) {
      for (int k = 0; k < 2; k++) {
        col[i][k] = state[Nb * i + j][k];
      }
    }

    uint8_t a[4][2];
    uint8_t b[4][2];
    uint8_t h[2];
    uint8_t no = 0x1B;
    clear_array(4, 2, a);
    clear_array(4, 2, b);
    bzero(h, 2);

    for (int c = 0; c < 4; c++) {
      uint8_t t[2];

      // a[c] = col[c];
      memcpy(a[c], col[c], 2);
      // h = (uint8_t)((signed char)col[c] >> 7);

      h[0] = (uint8_t)((signed char)col[c][0] >> 7);
      h[1] = (uint8_t)((signed char)col[c][1] >> 7);

      // b[c] = col[c] << 1;
      mpc_LEFTSHIFT2_u8(col[c], 1, b[c]);
      // b[c] ^= 0x1B & h; ==
      // t = 0x1B & h; b[c] = b[c] ^ t
      if (mpc_ANDK_verify_u8(h, no, t, pve, pve1, randomness, randCount,
                             countY) == FAIL)
        error_handler(__LINE__, "ANDK");
      mpc_XOR2_u8(b[c], t, b[c]);
    }

    uint8_t t0[2];

    // col[0] = b[0] ^ a[3] ^ a[2] ^ b[1] ^ a[1]; /* 2 * a0 + a3 + a2 + 3 * a1
    // */
    mpc_XOR2_u8(b[0], a[3], t0);
    mpc_XOR2_u8(t0, a[2], t0);
    mpc_XOR2_u8(t0, b[1], t0);
    mpc_XOR2_u8(t0, a[1], col[0]);

    // col[1] = b[1] ^ a[0] ^ a[3] ^ b[2] ^ a[2]; /* 2 * a1 + a0 + a3 + 3 * a2
    // */
    mpc_XOR2_u8(b[1], a[0], t0);
    mpc_XOR2_u8(t0, a[3], t0);
    mpc_XOR2_u8(t0, b[2], t0);
    mpc_XOR2_u8(t0, a[2], col[1]);

    // col[2] = b[2] ^ a[1] ^ a[0] ^ b[3] ^ a[3]; /* 2 * a2 + a1 + a0 + 3 * a3
    // */
    mpc_XOR2_u8(b[2], a[1], t0);
    mpc_XOR2_u8(t0, a[0], t0);
    mpc_XOR2_u8(t0, b[3], t0);
    mpc_XOR2_u8(t0, a[3], col[2]);

    // col[3] = b[3] ^ a[2] ^ a[1] ^ b[0] ^ a[0]; /* 2 * a3 + a2 + a1 + 3 * a0
    // */
    mpc_XOR2_u8(b[3], a[2], t0);
    mpc_XOR2_u8(t0, a[1], t0);
    mpc_XOR2_u8(t0, b[0], t0);
    mpc_XOR2_u8(t0, a[0], col[3]);

    for (int i = 0; i < 4; i++) {
      for (int k = 0; k < 2; k++) {
        state[Nb * i + j][k] = col[i][k];
      }
    }
  }
  return PASS;
}

void mpc_shift_rows(uint8_t state[][2]) {
  uint8_t i, j, k, s, tmp;

  for (i = 1; i < 4; i++) {
    s = 0;
    while (s < i) {
      for (j = 0; j < 2; j++) {
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

int mpc_sub_bytes(uint8_t state[][2], View* pve, View* pve1,
                  unsigned char* randomness[2], int* randCount, int* countY) {
  uint8_t i, j;
  // uint8_t t0[2] = {0xf0, 0xf0};
  // uint8_t t1[2] = {0x0f, 0x0f};

  uint8_t t0 = 0xf0;
  uint8_t t1 = 0x0f;

  // struct View* pve = &z.ve;
  // struct View* pve1 = &z.ve1;

  for (i = 0; i < 4; i++) {
    for (j = 0; j < Nb; j++) {
      uint8_t buf[2];
      uint8_t row[2];
      uint8_t col[2];
      uint8_t index[2];

      bzero(buf, 2);
      bzero(row, 2);
      bzero(col, 2);
      bzero(index, 2);

      if (mpc_ANDK_verify_u8(state[Nb * i + j], t0, row, pve, pve1, randomness,
                             randCount, countY) == FAIL)
        error_handler(__LINE__, "ANDK");
      if (mpc_ANDK_verify_u8(state[Nb * i + j], t1, col, pve, pve1, randomness,
                             randCount, countY) == FAIL)
        error_handler(__LINE__, "ANDK");

      if (mpc_ADD_verify_u8(row, col, index, pve, pve1, randomness, randCount,
                            countY) == FAIL)
        error_handler(__LINE__, "ADD");

      mpc_small_sbox(state[Nb * i + j], index, pve, pve1, randomness, randCount,
                     countY);
    }
  }
  return PASS;
}

int aes(unsigned char* results[2], unsigned char* inputs[2], View* pve,
        View* pve1, int numBytes, unsigned char* randomness[2], int* randCount,
        int* countY) {
  // int* randCount = calloc(1, sizeof(int));

  int msg_len = numBytes - 16 - Nb * (Nr + 1) * 4;

  if (msg_len % 16 != 0) {
    printf("Input not paddded (msg_size: %d)\n", msg_len);
    exit(0);
  }

  uint8_t padding_len = 16 - (msg_len - 1) % 16 - 1;
  int block_no = (padding_len + msg_len) / AES_BLOCK_SIZE;

  msg_len = msg_len + padding_len;

  // prepare inputs
  uint8_t w[Nb * (Nr + 1) * 4][2];
  uint8_t iv[AES_BLOCK_SIZE][2];
  uint8_t msg[msg_len][2];

  clear_array(AES_BLOCK_SIZE, 2, iv);
  clear_array(msg_len, 2, msg);
  clear_array(Nb * (Nr + 1) * 4, 2, w);

  for (int i = 0; i < AES_BLOCK_SIZE; i++) {
    for (int j = 0; j < 2; j++) {
      iv[i][j] = inputs[j][i];
    }
  }

  for (int i = 0; i < Nb * (Nr + 1) * 4; i++) {
    for (int j = 0; j < 2; j++) {
      w[i][j] = inputs[j][i + 16];
    }
  }

  for (int i = 0; i < msg_len; i++) {
    for (int j = 0; j < 2; j++) {
      if (i < msg_len - padding_len) {
        msg[i][j] = inputs[j][i + 16 + 176];
      } else {
        msg[i][j] = 0;
      }
    }
  }

  for (int blk = 0; blk < block_no; blk++) {
    uint8_t state[4 * Nb][2];
    clear_array(4 * Nb, 2, state);

    for (int m = 0; m < 4; m++) {
      for (int n = 0; n < Nb; n++) {
        for (int i = 0; i < 2; i++) {
          state[Nb * m + n][i] = msg[m + 4 * n + blk * AES_BLOCK_SIZE][i];
          if (blk == 0) {
            state[Nb * m + n][i] ^= iv[m + 4 * n][i];
          } else {
            state[Nb * m + n][i] ^=
                results[i][m + 4 * n + (blk - 1) * AES_BLOCK_SIZE];
          }
        }
      }
    }

    // aes encryptioin
    mpc_add_round_key(state, w, 0);

    for (int r = 1; r < Nr; r++) {
      mpc_sub_bytes(state, pve, pve1, randomness, randCount, countY);

      mpc_shift_rows(state);
      mpc_mix_columns(state, pve, pve1, randomness, randCount, countY);
      mpc_add_round_key(state, w, r);
    }

    mpc_sub_bytes(state, pve, pve1, randomness, randCount, countY);
    mpc_shift_rows(state);
    mpc_add_round_key(state, w, Nr);

    // copy results
    for (int m = 0; m < 4; m++) {
      for (int n = 0; n < Nb; n++) {
        for (int i = 0; i < 2; i++) {
          results[i][m + 4 * n + blk * AES_BLOCK_SIZE] = state[Nb * m + n][i];
        }
      }
    }
  }

  return 0;
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

  int input_len = IV_LEN + AES_EXPANDED_KEYS_LEN + INPUT_LEN;

  unsigned char* randomness[2];
  randomness[0] = calloc(RANDOMNESS_LEN, sizeof(unsigned char));
  randomness[1] = calloc(RANDOMNESS_LEN, sizeof(unsigned char));
  get_all_randomness(z.ke, randomness[0]);
  get_all_randomness(z.ke1, randomness[1]);

  int* randCount = calloc(1, sizeof(int));
  int* countY = calloc(1, sizeof(int));

  unsigned char* results[2];
  results[0] = calloc(OUTPUT_LEN, sizeof(unsigned char));
  results[1] = calloc(OUTPUT_LEN, sizeof(unsigned char));

  unsigned char* w[2];
  w[0] = calloc(input_len, sizeof(unsigned char));
  w[1] = calloc(input_len, sizeof(unsigned char));

  memcpy(w[0], z.ve.x, input_len);
  memcpy(w[1], z.ve1.x, input_len);

  aes(results, w, &z.ve, &z.ve1, input_len, randomness, randCount, countY);

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
  printf("Ciphertext: ");
	for (int i = 0; i < CIPHER_LEN; i++) {
		printf("%02X", y[i]);
	}
	printf("\n");

  printf("Plaintext: ");
	for (int i = CIPHER_LEN; i < OUTPUT_LEN; i++) {
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
