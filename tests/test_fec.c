/*
 * Unit test for FEC block manager (fec.c).
 * Tests the full TX encode → simulate loss → RX recover pipeline.
 * Build: cc -I include -o tests/test_fec tests/test_fec.c src/fec.c src/rs.c
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "fec.h"

static int tests_passed = 0;
static int tests_failed = 0;

#define ASSERT(cond, msg) do { \
    if (!(cond)) { \
        printf("  FAIL: %s\n", msg); \
        tests_failed++; \
        return; \
    } \
} while(0)

#define PASS(msg) do { \
    printf("  PASS: %s\n", msg); \
    tests_passed++; \
} while(0)

/* Test 1: TX block buffering and full detection */
static void test_tx_block_fill(void)
{
    struct fec_tx_block blk;
    memset(&blk, 0, sizeof(blk));
    fec_tx_reset_block(&blk, 0);

    uint8_t pkt[] = "Hello";
    for (int i = 0; i < RS_K - 1; i++) {
        int full = fec_tx_buffer_packet(&blk, pkt, 5, 100 + i * 5);
        ASSERT(full == 0, "block should not be full yet");
    }
    int full = fec_tx_buffer_packet(&blk, pkt, 5, 100 + (RS_K-1)*5);
    ASSERT(full == 1, "block should be full after k packets");
    ASSERT(blk.count == RS_K, "count should equal RS_K");
    PASS("TX block fill detection");

    fec_tx_reset_block(&blk, 1);
}

/* Test 2: Parity generation produces non-zero data */
static void test_parity_generation(void)
{
    struct fec_tx_block blk;
    memset(&blk, 0, sizeof(blk));
    fec_tx_reset_block(&blk, 0);

    char *packets[] = {"AAAA", "BBBB", "CCCC", "DDDD", "EEEE"};
    for (int i = 0; i < RS_K; i++) {
        fec_tx_buffer_packet(&blk, (uint8_t *)packets[i], 4, i * 100);
    }

    uint8_t *parity_bufs[RS_PARITY];
    uint16_t sym_len;
    fec_tx_generate_parity(&blk, parity_bufs, &sym_len);

    ASSERT(sym_len == 4, "symbol_len should match max payload");

    int all_zero = 1;
    for (int p = 0; p < RS_PARITY; p++) {
        for (int j = 0; j < sym_len; j++) {
            if (parity_bufs[p][j] != 0) all_zero = 0;
        }
        free(parity_bufs[p]);
    }
    ASSERT(!all_zero, "parity should not be all zeros");
    PASS("parity generation produces data");

    fec_tx_reset_block(&blk, 1);
}

/* Test 3: Full pipeline — encode, lose 1 packet, recover */
static void test_full_pipeline_lose_one(void)
{
    struct fec_tx_block tx;
    memset(&tx, 0, sizeof(tx));
    fec_tx_reset_block(&tx, 42);

    /* 5 distinct packets */
    uint8_t packets[RS_K][8] = {
        {0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x20, 0x30, 0x00}, /* Hello 0 */
        {0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x20, 0x31, 0x00}, /* Hello 1 */
        {0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x20, 0x32, 0x00}, /* Hello 2 */
        {0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x20, 0x33, 0x00}, /* Hello 3 */
        {0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x20, 0x34, 0x00}, /* Hello 4 */
    };

    for (int i = 0; i < RS_K; i++) {
        fec_tx_buffer_packet(&tx, packets[i], 8, i * 100);
    }

    uint8_t *parity_bufs[RS_PARITY];
    uint16_t sym_len;
    fec_tx_generate_parity(&tx, parity_bufs, &sym_len);

    /* === Simulate RX side === */
    struct fec_rx_block rx;
    memset(&rx, 0, sizeof(rx));
    fec_rx_reset_block(&rx, 42);

    /* Receive packets 0, 1, 3, 4 (packet 2 is lost) */
    fec_rx_add_data(&rx, 0, packets[0], 8);
    fec_rx_add_data(&rx, 1, packets[1], 8);
    /* packet 2 is LOST */
    fec_rx_add_data(&rx, 3, packets[3], 8);
    fec_rx_add_data(&rx, 4, packets[4], 8);

    ASSERT(rx.data_count == 4, "should have 4 data packets");

    /* Receive all parity */
    for (int p = 0; p < RS_PARITY; p++) {
        fec_rx_add_parity(&rx, p, parity_bufs[p], sym_len, sym_len);
    }

    ASSERT(fec_rx_can_recover(&rx), "should be recoverable with 4 data + 2 parity");

    int rc = fec_rx_recover(&rx);
    ASSERT(rc == 0, "recovery should succeed");

    /* Verify recovered packet 2 */
    ASSERT(rx.data_bufs[2] != NULL, "recovered buffer should not be NULL");
    ASSERT(memcmp(rx.data_bufs[2], packets[2], 8) == 0,
           "recovered packet 2 should match original");
    PASS("full pipeline: lose 1 of 5 packets, recover");

    for (int p = 0; p < RS_PARITY; p++) free(parity_bufs[p]);
    fec_tx_reset_block(&tx, 0);
    fec_rx_reset_block(&rx, 0);
}

/* Test 4: Lose 2 packets, recover */
static void test_full_pipeline_lose_two(void)
{
    struct fec_tx_block tx;
    memset(&tx, 0, sizeof(tx));
    fec_tx_reset_block(&tx, 99);

    uint8_t packets[RS_K][6] = {
        {0x01, 0x02, 0x03, 0x04, 0x05, 0x06},
        {0x11, 0x12, 0x13, 0x14, 0x15, 0x16},
        {0x21, 0x22, 0x23, 0x24, 0x25, 0x26},
        {0x31, 0x32, 0x33, 0x34, 0x35, 0x36},
        {0x41, 0x42, 0x43, 0x44, 0x45, 0x46},
    };

    for (int i = 0; i < RS_K; i++) {
        fec_tx_buffer_packet(&tx, packets[i], 6, i * 50);
    }

    uint8_t *parity_bufs[RS_PARITY];
    uint16_t sym_len;
    fec_tx_generate_parity(&tx, parity_bufs, &sym_len);

    /* RX: lose packets 0 and 3 */
    struct fec_rx_block rx;
    memset(&rx, 0, sizeof(rx));
    fec_rx_reset_block(&rx, 99);

    fec_rx_add_data(&rx, 1, packets[1], 6);
    fec_rx_add_data(&rx, 2, packets[2], 6);
    fec_rx_add_data(&rx, 4, packets[4], 6);

    for (int p = 0; p < RS_PARITY; p++) {
        fec_rx_add_parity(&rx, p, parity_bufs[p], sym_len, sym_len);
    }

    ASSERT(fec_rx_can_recover(&rx), "should be recoverable (3 data + 2 parity >= 5)");

    int rc = fec_rx_recover(&rx);
    ASSERT(rc == 0, "recovery should succeed");
    ASSERT(memcmp(rx.data_bufs[0], packets[0], 6) == 0, "packet 0 recovered");
    ASSERT(memcmp(rx.data_bufs[3], packets[3], 6) == 0, "packet 3 recovered");
    PASS("full pipeline: lose 2 of 5 packets, recover both");

    for (int p = 0; p < RS_PARITY; p++) free(parity_bufs[p]);
    fec_tx_reset_block(&tx, 0);
    fec_rx_reset_block(&rx, 0);
}

/* Test 5: Lose 3 packets — should NOT be recoverable (only 2 parity) */
static void test_pipeline_unrecoverable(void)
{
    struct fec_tx_block tx;
    memset(&tx, 0, sizeof(tx));
    fec_tx_reset_block(&tx, 7);

    uint8_t packets[RS_K][4] = {
        {0xAA, 0xBB, 0xCC, 0xDD},
        {0x11, 0x22, 0x33, 0x44},
        {0x55, 0x66, 0x77, 0x88},
        {0x99, 0xAA, 0xBB, 0xCC},
        {0xDD, 0xEE, 0xFF, 0x00},
    };

    for (int i = 0; i < RS_K; i++) {
        fec_tx_buffer_packet(&tx, packets[i], 4, i * 10);
    }

    uint8_t *parity_bufs[RS_PARITY];
    uint16_t sym_len;
    fec_tx_generate_parity(&tx, parity_bufs, &sym_len);

    struct fec_rx_block rx;
    memset(&rx, 0, sizeof(rx));
    fec_rx_reset_block(&rx, 7);

    /* Only receive 2 data packets + 2 parity = 4 < k=5 */
    fec_rx_add_data(&rx, 0, packets[0], 4);
    fec_rx_add_data(&rx, 2, packets[2], 4);
    for (int p = 0; p < RS_PARITY; p++) {
        fec_rx_add_parity(&rx, p, parity_bufs[p], sym_len, sym_len);
    }

    ASSERT(!fec_rx_can_recover(&rx), "should NOT be recoverable (3 losses > 2 parity)");
    PASS("unrecoverable loss correctly detected");

    for (int p = 0; p < RS_PARITY; p++) free(parity_bufs[p]);
    fec_tx_reset_block(&tx, 0);
    fec_rx_reset_block(&rx, 0);
}

/* Test 6: Variable-length packets (shorter packets zero-padded) */
static void test_variable_length_packets(void)
{
    struct fec_tx_block tx;
    memset(&tx, 0, sizeof(tx));
    fec_tx_reset_block(&tx, 0);

    uint8_t p0[] = {0x41, 0x42};                          /* 2 bytes */
    uint8_t p1[] = {0x43, 0x44, 0x45, 0x46, 0x47};        /* 5 bytes */
    uint8_t p2[] = {0x48};                                  /* 1 byte */
    uint8_t p3[] = {0x49, 0x4A, 0x4B};                     /* 3 bytes */
    uint8_t p4[] = {0x4C, 0x4D, 0x4E, 0x4F};              /* 4 bytes */

    fec_tx_buffer_packet(&tx, p0, 2, 0);
    fec_tx_buffer_packet(&tx, p1, 5, 100);
    fec_tx_buffer_packet(&tx, p2, 1, 200);
    fec_tx_buffer_packet(&tx, p3, 3, 300);
    fec_tx_buffer_packet(&tx, p4, 4, 400);

    ASSERT(tx.max_len == 5, "max_len should be 5");

    uint8_t *parity_bufs[RS_PARITY];
    uint16_t sym_len;
    fec_tx_generate_parity(&tx, parity_bufs, &sym_len);
    ASSERT(sym_len == 5, "symbol_len should be 5");

    /* RX: lose packet 1 (the longest one) */
    struct fec_rx_block rx;
    memset(&rx, 0, sizeof(rx));
    fec_rx_reset_block(&rx, 0);

    fec_rx_add_data(&rx, 0, p0, 2);
    /* p1 lost */
    fec_rx_add_data(&rx, 2, p2, 1);
    fec_rx_add_data(&rx, 3, p3, 3);
    fec_rx_add_data(&rx, 4, p4, 4);

    for (int p = 0; p < RS_PARITY; p++) {
        fec_rx_add_parity(&rx, p, parity_bufs[p], sym_len, sym_len);
    }

    ASSERT(fec_rx_can_recover(&rx), "should be recoverable");
    int rc = fec_rx_recover(&rx);
    ASSERT(rc == 0, "recovery should succeed");

    /* Check recovered data (note: recovery produces sym_len bytes, zero-padded) */
    ASSERT(memcmp(rx.data_bufs[1], p1, 5) == 0, "packet 1 fully recovered");
    PASS("variable-length packets: recover longest packet");

    for (int p = 0; p < RS_PARITY; p++) free(parity_bufs[p]);
    fec_tx_reset_block(&tx, 0);
    fec_rx_reset_block(&rx, 0);
}

int main(void)
{
    printf("=== FEC Block Manager Unit Tests ===\n");
    printf("RS(%d,%d) — %d data packets, %d parity packets\n\n", RS_N, RS_K, RS_K, RS_PARITY);

    rs_init();

    test_tx_block_fill();
    test_parity_generation();
    test_full_pipeline_lose_one();
    test_full_pipeline_lose_two();
    test_pipeline_unrecoverable();
    test_variable_length_packets();

    printf("\n=== Results: %d passed, %d failed ===\n",
           tests_passed, tests_failed);

    return tests_failed > 0 ? 1 : 0;
}
