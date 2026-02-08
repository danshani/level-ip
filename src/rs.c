#include "rs.h"
#include <string.h>

/*
 * Reed-Solomon over GF(2^8) with primitive polynomial x^8+x^4+x^3+x^2+1
 * (0x11d).  This is the same field used by CCSDS, RAID-6, etc.
 */

static uint8_t gf_exp[512]; /* anti-log table (doubled for mod) */
static uint8_t gf_log[256]; /* log table */
static int rs_initialised = 0;

/* Generator polynomial coefficients (RS_PARITY+1 terms, monic) */
static uint8_t gen_poly[RS_PARITY + 1];

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
     * Build generator polynomial g(x) = prod_{i=0}^{RS_PARITY-1} (x - alpha^i)
     * stored with gen_poly[0] = highest-degree coeff (=1).
     */
    memset(gen_poly, 0, sizeof(gen_poly));
    gen_poly[0] = 1;
    for (int i = 0; i < RS_PARITY; i++) {
        /* Multiply current poly by (x - alpha^i) */
        for (int j = RS_PARITY; j > 0; j--) {
            gen_poly[j] = gf_mul(gen_poly[j], gf_exp[i]) ^ gen_poly[j - 1];
        }
        gen_poly[0] = gf_mul(gen_poly[0], gf_exp[i]);
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

static uint8_t gf_div(uint8_t a, uint8_t b)
{
    if (a == 0) return 0;
    if (b == 0) return 0; /* error, but don't crash */
    return gf_exp[(gf_log[a] + 255 - gf_log[b]) % 255];
}

/*
 * Systematic RS encoding.
 * Treat data[0..k-1] as coefficients of a degree-(k-1) polynomial d(x).
 * Parity = remainder of x^(n-k) * d(x) / g(x).
 */
void rs_encode(const uint8_t data[RS_K], uint8_t parity[RS_PARITY])
{
    uint8_t feedback;
    memset(parity, 0, RS_PARITY);

    for (int i = 0; i < RS_K; i++) {
        feedback = data[i] ^ parity[0];
        /* Shift register */
        for (int j = 0; j < RS_PARITY - 1; j++) {
            parity[j] = parity[j + 1] ^ gf_mul(feedback, gen_poly[j + 1]);
        }
        parity[RS_PARITY - 1] = gf_mul(feedback, gen_poly[RS_PARITY]);
    }
}

/*
 * Erasure-only RS decoder.
 *
 * Given a codeword with known erasure positions, solve for the missing
 * symbols using the Vandermonde-like structure of RS codes.
 *
 * We evaluate syndromes, then solve the linear system defined by the
 * erasure locator/evaluator.
 */
int rs_decode(uint8_t block[RS_N], const int erasures[], int num_erasures)
{
    if (num_erasures == 0) return 0;
    if (num_erasures > RS_PARITY) return -1;

    /* Step 1: Compute syndromes S_i = sum_j block[j] * alpha^(i*j), i=0..RS_PARITY-1 */
    uint8_t syndromes[RS_PARITY];
    memset(syndromes, 0, sizeof(syndromes));

    for (int i = 0; i < RS_PARITY; i++) {
        uint8_t s = 0;
        for (int j = 0; j < RS_N; j++) {
            s = gf_add(s, gf_mul(block[j], gf_exp[(i * j) % 255]));
        }
        syndromes[i] = s;
    }

    /* Step 2: Build erasure locator polynomial Λ(x) = prod (1 - alpha^e_i * x) */
    uint8_t lambda[RS_PARITY + 1];
    memset(lambda, 0, sizeof(lambda));
    lambda[0] = 1;
    for (int i = 0; i < num_erasures; i++) {
        uint8_t x_val = gf_exp[erasures[i]];
        for (int j = num_erasures; j > 0; j--) {
            lambda[j] = gf_add(lambda[j], gf_mul(x_val, lambda[j - 1]));
        }
    }

    /* Step 3: Compute error evaluator Ω(x) = S(x)*Λ(x) mod x^RS_PARITY */
    uint8_t omega[RS_PARITY];
    memset(omega, 0, sizeof(omega));
    for (int i = 0; i < RS_PARITY; i++) {
        uint8_t val = 0;
        for (int j = 0; j <= i; j++) {
            val = gf_add(val, gf_mul(syndromes[j], lambda[i - j]));
        }
        omega[i] = val;
    }

    /* Step 4: Forney's algorithm – compute error values */
    for (int i = 0; i < num_erasures; i++) {
        /* Evaluate Ω(xi_inv) */
        uint8_t omega_val = 0;
        for (int j = 0; j < RS_PARITY; j++) {
            omega_val = gf_add(omega_val, gf_mul(omega[j], gf_exp[(j * (255 - erasures[i])) % 255]));
        }

        /* Evaluate Λ'(xi_inv) – formal derivative */
        uint8_t lambda_prime = 0;
        for (int j = 1; j <= num_erasures; j += 2) {
            lambda_prime = gf_add(lambda_prime, gf_mul(lambda[j], gf_exp[((j - 1) * (255 - erasures[i])) % 255]));
        }

        if (lambda_prime == 0) return -1; /* shouldn't happen */

        uint8_t error_val = gf_div(omega_val, lambda_prime);
        block[erasures[i]] = gf_add(block[erasures[i]], error_val);
    }

    return 0;
}
