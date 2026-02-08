#include "rs.h"
#include <string.h>

/*
 * Reed-Solomon over GF(2^8) with primitive polynomial x^8+x^4+x^3+x^2+1
 * (0x11d).  This is the same field used by CCSDS, RAID-6, etc.
 */

static uint8_t gf_exp[512]; /* anti-log table (doubled for mod) */
static uint8_t gf_log[256]; /* log table */
static int rs_initialised = 0;

/*
 * Generator polynomial non-leading coefficients, stored low-to-high.
 * g(x) = x^RS_PARITY + gp[RS_PARITY-1]*x^(RS_PARITY-1) + ... + gp[0]
 * We only store gp[0..RS_PARITY-1] since the leading coeff is always 1.
 */
static uint8_t gp[RS_PARITY];

void rs_init(void)
{
    if (rs_initialised) return;
    rs_initialised = 1;

    /* Build exp/log tables */
    uint16_t x = 1;
    for (int i = 0; i < 255; i++) {
        gf_exp[i] = (uint8_t)x;
        gf_log[x] = (uint8_t)i;
        x <<= 1;
        if (x & 0x100)
            x ^= 0x11d;
    }
    for (int i = 255; i < 512; i++) {
        gf_exp[i] = gf_exp[i - 255];
    }
    gf_log[0] = 0; /* convention; never used for valid mul */

    /*
     * Build generator polynomial g(x) = prod_{i=0}^{RS_PARITY-1} (x + alpha^i)
     * We store the full polynomial in tmp[0..RS_PARITY] where
     * tmp[j] = coefficient of x^j (low-to-high).
     * tmp[RS_PARITY] is always 1 (monic).
     */
    uint8_t tmp[RS_PARITY + 1];
    memset(tmp, 0, sizeof(tmp));
    tmp[0] = 1; /* start with g(x) = 1 */
    int deg = 0;

    for (int i = 0; i < RS_PARITY; i++) {
        /* Multiply tmp by (x + alpha^i) */
        deg++;
        for (int j = deg; j > 0; j--) {
            tmp[j] = tmp[j - 1] ^ gf_mul(tmp[j], gf_exp[i]);
        }
        tmp[0] = gf_mul(tmp[0], gf_exp[i]);
    }

    /* Copy non-leading coefficients */
    for (int i = 0; i < RS_PARITY; i++) {
        gp[i] = tmp[i];
    }
}

uint8_t gf_add(uint8_t a, uint8_t b)
{
    return a ^ b;
}

uint8_t gf_mul(uint8_t a, uint8_t b)
{
    if (a == 0 || b == 0) return 0;
    return gf_exp[gf_log[a] + gf_log[b]];
}

uint8_t gf_inv(uint8_t a)
{
    if (a == 0) return 0; /* shouldn't happen */
    return gf_exp[255 - gf_log[a]];
}

/*
 * Systematic RS encoding via LFSR.
 *
 * The codeword is laid out as:
 *   C(x) = data[0]*x^(n-1) + data[1]*x^(n-2) + ... + data[k-1]*x^(n-k)
 *         + parity[RS_PARITY-1]*x^(RS_PARITY-1) + ... + parity[0]*x^0
 *
 * parity[] = remainder of (data polynomial * x^(n-k)) / g(x).
 */
void rs_encode(const uint8_t data[RS_K], uint8_t parity[RS_PARITY])
{
    uint8_t reg[RS_PARITY];
    memset(reg, 0, RS_PARITY);

    for (int i = 0; i < RS_K; i++) {
        uint8_t fb = data[i] ^ reg[RS_PARITY - 1];
        for (int j = RS_PARITY - 1; j > 0; j--) {
            reg[j] = reg[j - 1] ^ gf_mul(fb, gp[j]);
        }
        reg[0] = gf_mul(fb, gp[0]);
    }

    /* Output parity in the order matching codeword layout:
     * parity[0] = reg[RS_PARITY-1]  (highest-power parity coeff first)
     * parity[1] = reg[RS_PARITY-2]
     * ...
     * This way codeword = [data[0], ..., data[k-1], parity[0], ..., parity[RS_PARITY-1]]
     * and parity[i] corresponds to x^(RS_PARITY-1-i).
     */
    for (int i = 0; i < RS_PARITY; i++) {
        parity[i] = reg[RS_PARITY - 1 - i];
    }
}

/*
 * Erasure-only RS decoder using direct linear algebra.
 *
 * The codeword C(x) = c[0]*x^(n-1) + c[1]*x^(n-2) + ... + c[n-1]
 * satisfies C(alpha^i) = 0 for i = 0..RS_PARITY-1.
 *
 * Syndromes: S_i = sum_j c[j] * alpha^(i*(n-1-j))
 *
 * For erased positions, we solve the linear system via Gaussian elimination.
 */
int rs_decode(uint8_t block[RS_N], const int erasures[], int num_erasures)
{
    if (num_erasures == 0) return 0;
    if (num_erasures > RS_PARITY) return -1;

    /* Compute syndromes: S_i = sum_j block[j] * alpha^(i*(n-1-j)) */
    uint8_t syndromes[RS_PARITY];
    for (int i = 0; i < RS_PARITY; i++) {
        uint8_t s = 0;
        for (int j = 0; j < RS_N; j++) {
            int power = i * (RS_N - 1 - j);
            uint8_t alpha_p = gf_exp[power % 255];
            if (power == 0) alpha_p = 1;
            s ^= gf_mul(block[j], alpha_p);
        }
        syndromes[i] = s;
    }

    /*
     * Build linear system: for each syndrome equation, the contribution
     * of erased position e is block[e] * alpha^(i*(n-1-e)).
     * We want: sum_{e in erasures} x_e * alpha^(i*(n-1-e)) = S_i
     *
     * Matrix A[i][j] = alpha^(i*(n-1-erasures[j]))
     */
    uint8_t mat[RS_PARITY][RS_PARITY + 1];
    memset(mat, 0, sizeof(mat));

    for (int i = 0; i < num_erasures; i++) {
        for (int j = 0; j < num_erasures; j++) {
            int power = i * (RS_N - 1 - erasures[j]);
            mat[i][j] = gf_exp[power % 255];
            if (power == 0) mat[i][j] = 1;
        }
        mat[i][num_erasures] = syndromes[i];
    }

    /* Gaussian elimination with partial pivoting */
    for (int col = 0; col < num_erasures; col++) {
        int pivot = -1;
        for (int row = col; row < num_erasures; row++) {
            if (mat[row][col] != 0) { pivot = row; break; }
        }
        if (pivot == -1) return -1;

        if (pivot != col) {
            for (int k = 0; k <= num_erasures; k++) {
                uint8_t tmp = mat[col][k];
                mat[col][k] = mat[pivot][k];
                mat[pivot][k] = tmp;
            }
        }

        uint8_t inv = gf_inv(mat[col][col]);
        for (int k = col; k <= num_erasures; k++) {
            mat[col][k] = gf_mul(mat[col][k], inv);
        }

        for (int row = 0; row < num_erasures; row++) {
            if (row == col) continue;
            uint8_t factor = mat[row][col];
            if (factor == 0) continue;
            for (int k = col; k <= num_erasures; k++) {
                mat[row][k] ^= gf_mul(factor, mat[col][k]);
            }
        }
    }

    /* Write recovered values */
    for (int j = 0; j < num_erasures; j++) {
        block[erasures[j]] = mat[j][num_erasures];
    }

    return 0;
}
