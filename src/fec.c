#include "syshead.h"
#include "fec.h"
#include "rs.h"
#include <string.h>

void fec_init(struct fec_state *fs)
{
    memset(fs, 0, sizeof(*fs));
    fs->enabled = 1;
    rs_init();
    fec_tx_reset_block(&fs->tx_block, 0);
    fec_rx_reset_block(&fs->rx_block, 0);
}

void fec_tx_reset_block(struct fec_tx_block *blk, uint16_t new_id)
{
    for (int i = 0; i < RS_K; i++) {
        if (blk->data_bufs[i]) {
            free(blk->data_bufs[i]);
            blk->data_bufs[i] = NULL;
        }
    }
    blk->block_id = new_id;
    blk->count = 0;
    blk->max_len = 0;
    memset(blk->data_lens, 0, sizeof(blk->data_lens));
    memset(blk->data_seqs, 0, sizeof(blk->data_seqs));
}

void fec_rx_reset_block(struct fec_rx_block *blk, uint16_t new_id)
{
    for (int i = 0; i < RS_K; i++) {
        if (blk->data_bufs[i]) {
            free(blk->data_bufs[i]);
            blk->data_bufs[i] = NULL;
        }
    }
    for (int i = 0; i < RS_PARITY; i++) {
        if (blk->parity_bufs[i]) {
            free(blk->parity_bufs[i]);
            blk->parity_bufs[i] = NULL;
        }
    }
    blk->block_id = new_id;
    blk->symbol_len = 0;
    blk->data_count = 0;
    blk->parity_count = 0;
    blk->block_seq_start = 0;
    memset(blk->data_present, 0, sizeof(blk->data_present));
    memset(blk->parity_present, 0, sizeof(blk->parity_present));
    memset(blk->data_lens, 0, sizeof(blk->data_lens));
}

int fec_tx_buffer_packet(struct fec_tx_block *blk, const uint8_t *payload,
                         uint16_t len, uint32_t seq)
{
    if (blk->count >= RS_K) return 1; /* already full */

    int idx = blk->count;
    blk->data_bufs[idx] = malloc(len);
    memcpy(blk->data_bufs[idx], payload, len);
    blk->data_lens[idx] = len;
    blk->data_seqs[idx] = seq;
    if (len > blk->max_len)
        blk->max_len = len;
    blk->count++;

    return (blk->count >= RS_K) ? 1 : 0;
}

void fec_tx_generate_parity(struct fec_tx_block *blk, uint8_t *out_bufs[RS_PARITY],
                            uint16_t *out_len)
{
    uint16_t slen = blk->max_len;
    *out_len = slen;

    /* Allocate parity buffers */
    for (int p = 0; p < RS_PARITY; p++) {
        out_bufs[p] = malloc(slen);
        memset(out_bufs[p], 0, slen);
    }

    /* Encode column by column */
    for (uint16_t col = 0; col < slen; col++) {
        uint8_t data_col[RS_K];
        uint8_t parity_col[RS_PARITY];

        for (int i = 0; i < RS_K; i++) {
            if (col < blk->data_lens[i])
                data_col[i] = blk->data_bufs[i][col];
            else
                data_col[i] = 0; /* zero-pad shorter packets */
        }

        rs_encode(data_col, parity_col);

        for (int p = 0; p < RS_PARITY; p++) {
            out_bufs[p][col] = parity_col[p];
        }
    }
}

void fec_rx_add_data(struct fec_rx_block *blk, int index,
                     const uint8_t *payload, uint16_t len)
{
    if (index < 0 || index >= RS_K) return;
    if (blk->data_present[index]) return; /* duplicate */

    blk->data_bufs[index] = malloc(len);
    memcpy(blk->data_bufs[index], payload, len);
    blk->data_lens[index] = len;
    blk->data_present[index] = 1;
    blk->data_count++;
}

void fec_rx_add_parity(struct fec_rx_block *blk, int parity_idx,
                       const uint8_t *payload, uint16_t len, uint16_t symbol_len)
{
    if (parity_idx < 0 || parity_idx >= RS_PARITY) return;
    if (blk->parity_present[parity_idx]) return;

    blk->parity_bufs[parity_idx] = malloc(len);
    memcpy(blk->parity_bufs[parity_idx], payload, len);
    blk->parity_present[parity_idx] = 1;
    blk->parity_count++;
    if (symbol_len > blk->symbol_len)
        blk->symbol_len = symbol_len;
}

int fec_rx_can_recover(struct fec_rx_block *blk)
{
    int total = blk->data_count + blk->parity_count;
    int missing = RS_K - blk->data_count;
    return (total >= RS_K && missing <= RS_PARITY);
}

int fec_rx_recover(struct fec_rx_block *blk)
{
    if (!fec_rx_can_recover(blk)) return -1;

    uint16_t slen = blk->symbol_len;
    if (slen == 0) return -1;

    /* Determine erasure positions (indices into the RS_N-length codeword) */
    int erasures[RS_N];
    int num_erasures = 0;

    for (int i = 0; i < RS_K; i++) {
        if (!blk->data_present[i]) {
            erasures[num_erasures++] = i;
            /* Allocate a zero buffer for the missing data slot */
            blk->data_bufs[i] = malloc(slen);
            memset(blk->data_bufs[i], 0, slen);
            blk->data_lens[i] = slen;
        }
    }
    for (int i = 0; i < RS_PARITY; i++) {
        if (!blk->parity_present[i]) {
            erasures[num_erasures++] = RS_K + i;
            /* Allocate a zero buffer for the missing parity slot */
            blk->parity_bufs[i] = malloc(slen);
            memset(blk->parity_bufs[i], 0, slen);
        }
    }

    /* Decode column by column */
    for (uint16_t col = 0; col < slen; col++) {
        uint8_t codeword[RS_N];

        for (int i = 0; i < RS_K; i++) {
            codeword[i] = (col < blk->data_lens[i]) ? blk->data_bufs[i][col] : 0;
        }
        for (int i = 0; i < RS_PARITY; i++) {
            codeword[RS_K + i] = blk->parity_bufs[i] ? blk->parity_bufs[i][col] : 0;
        }

        if (rs_decode(codeword, erasures, num_erasures) != 0)
            return -1;

        /* Write back recovered data symbols */
        for (int i = 0; i < RS_K; i++) {
            if (!blk->data_present[i]) {
                blk->data_bufs[i][col] = codeword[i];
            }
        }
    }

    /* Mark recovered slots as present */
    for (int i = 0; i < RS_K; i++) {
        blk->data_present[i] = 1;
    }
    blk->data_count = RS_K;

    return 0;
}
