/*
 * Unit test for Reed-Solomon GF(2^8) codec.
 * Tests: encode → erasure → decode cycle.
 * Build: cc -I include -o tests/test_rs tests/test_rs.c src/rs.c
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "rs.h"

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

/* Test 1: Encode and verify parity is non-trivial */
static void test_encode_produces_parity(void)
{
    uint8_t data[RS_K] = {0x41, 0x42, 0x43, 0x44, 0x45}; /* "ABCDE" */
    uint8_t parity[RS_PARITY] = {0};

    rs_encode(data, parity);

    int all_zero = 1;
    for (int i = 0; i < RS_PARITY; i++)
        if (parity[i] != 0) all_zero = 0;

    ASSERT(!all_zero, "parity should not be all zeros for non-zero data");
    PASS("encode produces non-trivial parity");
}

/* Test 2: No erasures — block should be valid as-is */
static void test_decode_no_erasures(void)
{
    uint8_t data[RS_K] = {0x10, 0x20, 0x30, 0x40, 0x50};
    uint8_t parity[RS_PARITY];
    rs_encode(data, parity);

    uint8_t block[RS_N];
    memcpy(block, data, RS_K);
    memcpy(block + RS_K, parity, RS_PARITY);

    int rc = rs_decode(block, NULL, 0);
    ASSERT(rc == 0, "decode with no erasures should succeed");

    /* Data should be unchanged */
    ASSERT(memcmp(block, data, RS_K) == 0, "data should be unchanged");
    PASS("decode with no erasures preserves data");
}

/* Test 3: Erase 1 data symbol, recover it */
static void test_recover_one_data_erasure(void)
{
    uint8_t data[RS_K] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE};
    uint8_t parity[RS_PARITY];
    rs_encode(data, parity);

    uint8_t block[RS_N];
    memcpy(block, data, RS_K);
    memcpy(block + RS_K, parity, RS_PARITY);

    /* Erase position 2 */
    block[2] = 0x00;
    int erasures[] = {2};
    int rc = rs_decode(block, erasures, 1);

    ASSERT(rc == 0, "decode should succeed with 1 erasure");
    ASSERT(block[2] == 0xCC, "erased symbol should be recovered");
    PASS("recover 1 data erasure");
}

/* Test 4: Erase 2 data symbols (max for RS_PARITY=2), recover both */
static void test_recover_two_data_erasures(void)
{
    uint8_t data[RS_K] = {0x01, 0x02, 0x03, 0x04, 0x05};
    uint8_t parity[RS_PARITY];
    rs_encode(data, parity);

    uint8_t block[RS_N];
    memcpy(block, data, RS_K);
    memcpy(block + RS_K, parity, RS_PARITY);

    /* Erase positions 0 and 4 */
    block[0] = 0x00;
    block[4] = 0x00;
    int erasures[] = {0, 4};
    int rc = rs_decode(block, erasures, 2);

    ASSERT(rc == 0, "decode should succeed with 2 erasures");
    ASSERT(block[0] == 0x01, "position 0 should be recovered");
    ASSERT(block[4] == 0x05, "position 4 should be recovered");
    PASS("recover 2 data erasures (max capacity)");
}

/* Test 5: Erase 1 data + 1 parity, recover */
static void test_recover_mixed_erasure(void)
{
    uint8_t data[RS_K] = {0xFF, 0xFE, 0xFD, 0xFC, 0xFB};
    uint8_t parity[RS_PARITY];
    rs_encode(data, parity);

    uint8_t block[RS_N];
    memcpy(block, data, RS_K);
    memcpy(block + RS_K, parity, RS_PARITY);

    /* Erase data[1] and parity[0] */
    uint8_t saved_data1 = block[1];
    block[1] = 0x00;
    block[RS_K] = 0x00;
    int erasures[] = {1, RS_K};
    int rc = rs_decode(block, erasures, 2);

    ASSERT(rc == 0, "decode should succeed with mixed erasures");
    ASSERT(block[1] == saved_data1, "data[1] should be recovered");
    PASS("recover 1 data + 1 parity erasure");
}

/* Test 6: Too many erasures should fail */
static void test_too_many_erasures_fails(void)
{
    uint8_t data[RS_K] = {0x11, 0x22, 0x33, 0x44, 0x55};
    uint8_t parity[RS_PARITY];
    rs_encode(data, parity);

    uint8_t block[RS_N];
    memcpy(block, data, RS_K);
    memcpy(block + RS_K, parity, RS_PARITY);

    /* Erase 3 positions — more than RS_PARITY=2 */
    block[0] = 0; block[1] = 0; block[2] = 0;
    int erasures[] = {0, 1, 2};
    int rc = rs_decode(block, erasures, 3);

    ASSERT(rc == -1, "decode should fail with 3 erasures (max is 2)");
    PASS("too many erasures correctly rejected");
}

/* Test 7: Column-wise encoding (simulates multi-packet FEC) */
static void test_column_wise_fec(void)
{
    /* Simulate 5 packets of 4 bytes each */
    uint8_t packets[RS_K][4] = {
        {0x48, 0x65, 0x6C, 0x6C}, /* Hell */
        {0x6F, 0x20, 0x57, 0x6F}, /* o Wo */
        {0x72, 0x6C, 0x64, 0x21}, /* rld! */
        {0x0A, 0x46, 0x45, 0x43}, /* .FEC */
        {0x20, 0x4F, 0x4B, 0x21}, /*  OK! */
    };

    /* Encode column-by-column */
    uint8_t parity_pkts[RS_PARITY][4];
    for (int col = 0; col < 4; col++) {
        uint8_t data_col[RS_K];
        for (int i = 0; i < RS_K; i++)
            data_col[i] = packets[i][col];

        uint8_t par_col[RS_PARITY];
        rs_encode(data_col, par_col);

        for (int p = 0; p < RS_PARITY; p++)
            parity_pkts[p][col] = par_col[p];
    }

    /* Now erase packet 1 (index 1) and recover */
    uint8_t saved[4];
    memcpy(saved, packets[1], 4);
    memset(packets[1], 0, 4);

    for (int col = 0; col < 4; col++) {
        uint8_t codeword[RS_N];
        for (int i = 0; i < RS_K; i++)
            codeword[i] = packets[i][col];
        for (int p = 0; p < RS_PARITY; p++)
            codeword[RS_K + p] = parity_pkts[p][col];

        int erasures[] = {1};
        int rc = rs_decode(codeword, erasures, 1);
        ASSERT(rc == 0, "column decode should succeed");
        packets[1][col] = codeword[1];
    }

    ASSERT(memcmp(packets[1], saved, 4) == 0, "packet 1 fully recovered");
    PASS("column-wise FEC simulation (5 packets, erase 1, recover)");
}

int main(void)
{
    printf("=== Reed-Solomon Unit Tests ===\n");
    printf("RS(%d,%d) — %d data, %d parity\n\n", RS_N, RS_K, RS_K, RS_PARITY);

    rs_init();

    test_encode_produces_parity();
    test_decode_no_erasures();
    test_recover_one_data_erasure();
    test_recover_two_data_erasures();
    test_recover_mixed_erasure();
    test_too_many_erasures_fails();
    test_column_wise_fec();

    printf("\n=== Results: %d passed, %d failed ===\n",
           tests_passed, tests_failed);

    return tests_failed > 0 ? 1 : 0;
}
