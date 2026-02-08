#ifndef FEC_H_
#define FEC_H_

#include "syshead.h"
#include "skbuff.h"
#include "rs.h"

/*
 * FEC Block Header – prepended to the payload of every Parity Packet.
 * The receiver uses this to associate the parity with the correct block.
 */
struct fec_hdr {
    uint16_t block_id;       /* FEC block number (monotonically increasing) */
    uint8_t  seq_idx;        /* Index within the block (0..RS_PARITY-1 for parity) */
    uint8_t  pad_len;        /* reserved / padding info */
    uint16_t symbol_len;     /* Max payload length used for RS encoding */
    uint32_t block_seq_start;/* TCP seq of first data packet in this block */
    uint16_t mss;            /* MSS used by sender for seq reconstruction */
} __attribute__((packed));

#define FEC_HDR_LEN sizeof(struct fec_hdr)

/*
 * FEC Transmit Block – accumulates k data packets then generates parity.
 */
struct fec_tx_block {
    uint16_t block_id;
    int      count;                 /* number of data packets buffered so far */
    uint16_t max_len;               /* max payload length seen in this block */
    uint8_t *data_bufs[RS_K];       /* copies of data payloads (padded to max_len) */
    uint16_t data_lens[RS_K];       /* actual payload lengths */
    uint32_t data_seqs[RS_K];       /* sequence numbers of original data packets */
};

/*
 * FEC Receive Block – collects data + parity for one block on the receiver.
 */
struct fec_rx_block {
    uint16_t block_id;
    uint16_t symbol_len;            /* from fec_hdr of first parity seen */
    uint16_t mss;                   /* sender MSS, from fec_hdr */
    int      data_count;
    int      parity_count;
    uint8_t  data_present[RS_K];    /* 1 if data slot i was received */
    uint8_t  parity_present[RS_PARITY];
    uint8_t *data_bufs[RS_K];
    uint16_t data_lens[RS_K];
    uint8_t *parity_bufs[RS_PARITY];
    uint32_t block_seq_start;       /* seq number of first packet in block */
    uint32_t data_seqs[RS_K];       /* per-slot TCP sequence numbers */
    uint8_t  seq_known;             /* 1 once block_seq_start is set */
};

/*
 * Per-socket FEC state, embedded in tcp_sock.
 */
struct fec_state {
    int enabled;
    /* TX side */
    struct fec_tx_block tx_block;
    /* RX side */
    struct fec_rx_block rx_block;
};

/* API */
void fec_init(struct fec_state *fs);
void fec_tx_reset_block(struct fec_tx_block *blk, uint16_t new_id);
void fec_rx_reset_block(struct fec_rx_block *blk, uint16_t new_id);

/*
 * fec_tx_buffer_packet – copy a data packet payload into the TX block.
 * Returns 1 if the block is now full (count == RS_K) and parity should be sent.
 */
int fec_tx_buffer_packet(struct fec_tx_block *blk, const uint8_t *payload,
                         uint16_t len, uint32_t seq);

/*
 * fec_tx_generate_parity – produce RS_PARITY parity buffers.
 * @out_bufs[i] is allocated and filled with parity data for parity packet i.
 * @out_len is set to the symbol_len used (all parity bufs are this length).
 * Caller must free the out_bufs.
 */
void fec_tx_generate_parity(struct fec_tx_block *blk, uint8_t *out_bufs[RS_PARITY],
                            uint16_t *out_len);

/*
 * fec_rx_add_data – register reception of a data packet at a given index.
 */
void fec_rx_add_data(struct fec_rx_block *blk, int index,
                     const uint8_t *payload, uint16_t len);

/*
 * fec_rx_add_parity – register reception of a parity packet.
 */
void fec_rx_add_parity(struct fec_rx_block *blk, int parity_idx,
                       const uint8_t *payload, uint16_t len, uint16_t symbol_len);

/*
 * fec_rx_can_recover – check if we have enough data+parity to recover losses.
 */
int fec_rx_can_recover(struct fec_rx_block *blk);

/*
 * fec_rx_recover – perform RS decoding column-by-column.
 * Fills in missing data_bufs entries.  Returns 0 on success, -1 on failure.
 */
int fec_rx_recover(struct fec_rx_block *blk);

/*
 * fec_rx_seq_for_index – compute the TCP sequence number for a given
 * block slot index.  Returns block_seq_start + index * mss.
 */
uint32_t fec_rx_seq_for_index(struct fec_rx_block *blk, int index);

#endif
