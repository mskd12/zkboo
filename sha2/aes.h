#ifndef AES_H_
#define AES_H_

#include "define.h"
#include "shared.h"
#include "zklib.h"

uint8_t gadd(uint8_t a, uint8_t b) { return a ^ b; }

uint8_t gsub(uint8_t a, uint8_t b) { return a ^ b; }

uint8_t gmult(uint8_t a, uint8_t b) {
  uint8_t p = 0, i = 0, hbs = 0;

  for (i = 0; i < 8; i++) {
    if (b & 1) {
      p ^= a;
    }

    hbs = a & 0x80;
    a <<= 1;
    if (hbs) {
      a ^= 0x1b;  // 0000 0001 0001 1011
    }
    b >>= 1;
  }

  return (uint8_t)p;
}

void coef_add(uint8_t a[], uint8_t b[], uint8_t d[]) {
  d[0] = a[0] ^ b[0];
  d[1] = a[1] ^ b[1];
  d[2] = a[2] ^ b[2];
  d[3] = a[3] ^ b[3];
}

uint8_t R[] = {0x02, 0x00, 0x00, 0x00};

uint8_t *Rcon(uint8_t i) {
  if (i == 1) {
    R[0] = 0x01;  // x^(1-1) = x^0 = 1
  } else if (i > 1) {
    R[0] = 0x02;
    i--;
    while (i - 1 > 0) {
      R[0] = gmult(R[0], 0x02);
      i--;
    }
  }

  return R;
}

void add_round_key(uint8_t *state, uint8_t *w, uint8_t r) {
  uint8_t c;
  for (c = 0; c < Nb; c++) {
    state[Nb * 0 + c] = state[Nb * 0 + c] ^ w[4 * Nb * r + 4 * c + 0];
    state[Nb * 1 + c] = state[Nb * 1 + c] ^ w[4 * Nb * r + 4 * c + 1];
    state[Nb * 2 + c] = state[Nb * 2 + c] ^ w[4 * Nb * r + 4 * c + 2];
    state[Nb * 3 + c] = state[Nb * 3 + c] ^ w[4 * Nb * r + 4 * c + 3];
  }
}

uint8_t small_sbox(uint8_t n) {
  uint8_t U0, U1, U2, U3, U4, U5, U6, U7;
  uint8_t T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11, T12, T13, T14, T15, T16,
      T17, T18, T19, T20, T21, T22, T23, T24, T25, T26, T27;
  uint8_t M1, M2, M3, M4, M5, M6, M7, M8, M9, M10, M11, M12, M13, M14, M15, M16,
      M17, M18, M19, M20, M21, M22, M23, M24, M25, M26, M27, M28, M29, M30, M31,
      M32, M33, M34, M35, M36, M37, M38, M39, M40, M41, M42, M43, M44, M45, M46,
      M47, M48, M49, M50, M51, M52, M53, M54, M55, M56, M57, M58, M59, M60, M61,
      M62, M63;
  uint8_t L0, L1, L2, L3, L4, L5, L6, L7, L8, L9, L10, L11, L12, L13, L14, L15,
      L16, L17, L18, L19, L20, L21, L22, L23, L24, L25, L26, L27, L28, L29;
  uint8_t S0, S1, S2, S3, S4, S5, S6, S7;
  U0 = (n & (1 << 7)) >> 7;
  U1 = (n & (1 << 6)) >> 6;
  U2 = (n & (1 << 5)) >> 5;
  U3 = (n & (1 << 4)) >> 4;
  U4 = (n & (1 << 3)) >> 3;
  U5 = (n & (1 << 2)) >> 2;
  U6 = (n & (1 << 1)) >> 1;
  U7 = (n & (1 << 0)) >> 0;

  T1 = U0 ^ U3;
  T2 = U0 ^ U5;
  T3 = U0 ^ U6;
  T4 = U3 ^ U5;
  T5 = U4 ^ U6;
  T6 = T1 ^ T5;
  T7 = U1 ^ U2;
  T8 = U7 ^ T6;
  T9 = U7 ^ T7;
  T10 = T6 ^ T7;
  T11 = U1 ^ U5;
  T12 = U2 ^ U5;
  T13 = T3 ^ T4;
  T14 = T6 ^ T11;
  T15 = T5 ^ T11;
  T16 = T5 ^ T12;
  T17 = T9 ^ T16;
  T18 = U3 ^ U7;
  T19 = T7 ^ T18;
  T20 = T1 ^ T19;
  T21 = U6 ^ U7;
  T22 = T7 ^ T21;
  T23 = T2 ^ T22;
  T24 = T2 ^ T10;
  T25 = T20 ^ T17;
  T26 = T3 ^ T16;
  T27 = T1 ^ T12;
  M1 = T13 & T6;
  M2 = T23 & T8;
  M3 = T14 ^ M1;
  M4 = T19 & U7;
  M5 = M4 ^ M1;
  M6 = T3 & T16;
  M7 = T22 & T9;
  M8 = T26 ^ M6;
  M9 = T20 & T17;
  M10 = M9 ^ M6;
  M11 = T1 & T15;
  M12 = T4 & T27;
  M13 = M12 ^ M11;
  M14 = T2 & T10;
  M15 = M14 ^ M11;
  M16 = M3 ^ M2;
  M17 = M5 ^ T24;
  M18 = M8 ^ M7;
  M19 = M10 ^ M15;
  M20 = M16 ^ M13;
  M21 = M17 ^ M15;
  M22 = M18 ^ M13;
  M23 = M19 ^ T25;
  M24 = M22 ^ M23;
  M25 = M22 & M20;
  M26 = M21 ^ M25;
  M27 = M20 ^ M21;
  M28 = M23 ^ M25;
  M29 = M28 & M27;
  M30 = M26 & M24;
  M31 = M20 & M23;
  M32 = M27 & M31;
  M33 = M27 ^ M25;
  M34 = M21 & M22;
  M35 = M24 & M34;
  M36 = M24 ^ M25;
  M37 = M21 ^ M29;
  M38 = M32 ^ M33;
  M39 = M23 ^ M30;
  M40 = M35 ^ M36;
  M41 = M38 ^ M40;
  M42 = M37 ^ M39;
  M43 = M37 ^ M38;
  M44 = M39 ^ M40;
  M45 = M42 ^ M41;
  M46 = M44 & T6;
  M47 = M40 & T8;
  M48 = M39 & U7;
  M49 = M43 & T16;
  M50 = M38 & T9;
  M51 = M37 & T17;
  M52 = M42 & T15;
  M53 = M45 & T27;
  M54 = M41 & T10;
  M55 = M44 & T13;
  M56 = M40 & T23;
  M57 = M39 & T19;
  M58 = M43 & T3;
  M59 = M38 & T22;
  M60 = M37 & T20;
  M61 = M42 & T1;
  M62 = M45 & T4;
  M63 = M41 & T2;
  L0 = M61 ^ M62;
  L1 = M50 ^ M56;
  L2 = M46 ^ M48;
  L3 = M47 ^ M55;
  L4 = M54 ^ M58;
  L5 = M49 ^ M61;
  L6 = M62 ^ L5;
  L7 = M46 ^ L3;
  L8 = M51 ^ M59;
  L9 = M52 ^ M53;
  L10 = M53 ^ L4;
  L11 = M60 ^ L2;
  L12 = M48 ^ M51;
  L13 = M50 ^ L0;
  L14 = M52 ^ M61;
  L15 = M55 ^ L1;
  L16 = M56 ^ L0;
  L17 = M57 ^ L1;
  L18 = M58 ^ L8;
  L19 = M63 ^ L4;
  L20 = L0 ^ L1;
  L21 = L1 ^ L7;
  L22 = L3 ^ L12;
  L23 = L18 ^ L2;
  L24 = L15 ^ L9;
  L25 = L6 ^ L10;
  L26 = L7 ^ L9;
  L27 = L8 ^ L10;
  L28 = L11 ^ L14;
  L29 = L11 ^ L17;
  S0 = L6 ^ L24;
  S1 = XNOR(L16, L26);
  S2 = XNOR(L19, L28);

  S3 = L6 ^ L21;
  S4 = L20 ^ L22;
  S5 = L25 ^ L29;

  S6 = XNOR(L13, L27);
  S7 = XNOR(L6, L23);
  uint8_t res = (S0 << 7) | (S1 << 6) | (S2 << 5) | (S3 << 4) | (S4 << 3) |
                (S5 << 2) | (S6 << 1) | (S7 << 0);
  return res;
}

void mix_columns(uint8_t *state) {
  uint8_t i, j, col[4];

  for (j = 0; j < Nb; j++) {
    for (i = 0; i < 4; i++) {
      col[i] = state[Nb * i + j];
    }

    // coef_mult(a, col, res);
    unsigned char a[4];
    unsigned char b[4];
    unsigned char h;

    for (int c = 0; c < 4; c++) {
      a[c] = col[c];
      /* h is 0xff if the high bit of r[c] is set, 0 otherwise */
      h = (unsigned char)((signed char)col[c] >>
                          7); /* arithmetic right shift, thus shifting in either
                                 zeros or ones */
      b[c] = col[c]
             << 1; /* implicitly removes high bit because b[c] is an 8-bit char,
                      so we xor by 0x1b and not 0x11b in the next line */
      b[c] ^= 0x1B & h; /* Rijndael's Galois field */
    }
    col[0] = b[0] ^ a[3] ^ a[2] ^ b[1] ^ a[1]; /* 2 * a0 + a3 + a2 + 3 * a1 */
    col[1] = b[1] ^ a[0] ^ a[3] ^ b[2] ^ a[2]; /* 2 * a1 + a0 + a3 + 3 * a2 */
    col[2] = b[2] ^ a[1] ^ a[0] ^ b[3] ^ a[3]; /* 2 * a2 + a1 + a0 + 3 * a3 */
    col[3] = b[3] ^ a[2] ^ a[1] ^ b[0] ^ a[0]; /* 2 * a3 + a2 + a1 + 3 * a0 */

    for (i = 0; i < 4; i++) {
      state[Nb * i + j] = col[i];
    }
  }
}

void shift_rows(uint8_t *state) {
  uint8_t i, k, s, tmp;

  for (i = 1; i < 4; i++) {
    s = 0;
    while (s < i) {
      tmp = state[Nb * i + 0];

      for (k = 1; k < Nb; k++) {
        state[Nb * i + k - 1] = state[Nb * i + k];
      }

      state[Nb * i + Nb - 1] = tmp;
      s++;
    }
  }
}

void sub_bytes(uint8_t *state) {
  uint8_t i, j;
  uint8_t row, col;

  for (i = 0; i < 4; i++) {
    for (j = 0; j < Nb; j++) {
      row = (state[Nb * i + j] & 0xf0);
      col = state[Nb * i + j] & 0x0f;
      // state[Nb*i+j] = s_box[16*row+col];
      state[Nb * i + j] = small_sbox(row + col);
    }
  }
}

void sub_word(uint8_t *w) {
  uint8_t i;
  for (i = 0; i < 4; i++) {
    // w[i] = s_box[16*((w[i] & 0xf0) >> 4) + (w[i] & 0x0f)];
    w[i] = small_sbox((w[i] & 0xf0) + (w[i] & 0x0f));
  }
}

void rot_word(uint8_t *w) {
  uint8_t tmp;
  uint8_t i;

  tmp = w[0];
  for (i = 0; i < 3; i++) {
    w[i] = w[i + 1];
  }
  w[3] = tmp;
}

void key_expansion(uint8_t *key, uint8_t *w) {
  uint8_t tmp[4];
  uint8_t i;
  uint8_t len = Nb * (Nr + 1);

  for (i = 0; i < Nk; i++) {
    w[4 * i + 0] = key[4 * i + 0];
    w[4 * i + 1] = key[4 * i + 1];
    w[4 * i + 2] = key[4 * i + 2];
    w[4 * i + 3] = key[4 * i + 3];
  }

  for (i = Nk; i < len; i++) {
    tmp[0] = w[4 * (i - 1) + 0];
    tmp[1] = w[4 * (i - 1) + 1];
    tmp[2] = w[4 * (i - 1) + 2];
    tmp[3] = w[4 * (i - 1) + 3];

    if (i % Nk == 0) {
      rot_word(tmp);
      sub_word(tmp);
      coef_add(tmp, Rcon(i / Nk), tmp);

    } else if (Nk > 6 && i % Nk == 4) {
      sub_word(tmp);
    }

    w[4 * i + 0] = w[4 * (i - Nk) + 0] ^ tmp[0];
    w[4 * i + 1] = w[4 * (i - Nk) + 1] ^ tmp[1];
    w[4 * i + 2] = w[4 * (i - Nk) + 2] ^ tmp[2];
    w[4 * i + 3] = w[4 * (i - Nk) + 3] ^ tmp[3];
  }
}

#endif