#ifndef RS_H_
#define RS_H_

#include <stdint.h>

/*
 * Reed-Solomon codec over GF(2^8) with primitive polynomial 0x11d.
 *
 * Systematic encoding: first k symbols of codeword == data symbols.
 * This implementation operates on blocks of symbols where each "symbol"
 * is one byte.  To protect packets we treat each byte-position across
 * the k packets independently (i.e. column-wise RS).
 *
 * Parameters (compile-time for simplicity):
 *   RS_N  – total symbols per codeword  (data + parity)
 *   RS_K  – data symbols per codeword
 *   RS_N - RS_K  – parity symbols (= max correctable erasures)
 */

#define RS_N  7
#define RS_K  5
#define RS_PARITY (RS_N - RS_K)

/* GF(2^8) arithmetic */
uint8_t gf_add(uint8_t a, uint8_t b);
uint8_t gf_mul(uint8_t a, uint8_t b);
uint8_t gf_inv(uint8_t a);

/* Initialise lookup tables – call once at startup */
void rs_init(void);

/*
 * rs_encode – produce RS_PARITY parity symbols from RS_K data symbols.
 *
 * @data:   array of RS_K data bytes  (one column across k packets)
 * @parity: output array of RS_PARITY bytes
 */
void rs_encode(const uint8_t data[RS_K], uint8_t parity[RS_PARITY]);

/*
 * rs_decode – recover up to RS_PARITY erasures.
 *
 * @block:      array of RS_N bytes (data[0..k-1], parity[k..n-1]).
 *              Missing positions should be zeroed.
 * @erasures:   array of erased indices (values 0..RS_N-1)
 * @num_erasures: number of erasures (<= RS_PARITY)
 *
 * Returns 0 on success, -1 if too many erasures.
 * On success the erased positions in @block are filled in.
 */
int rs_decode(uint8_t block[RS_N], const int erasures[], int num_erasures);

#endif
