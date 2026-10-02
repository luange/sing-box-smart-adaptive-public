/*
 * C ABI for the optional Linux AF_XDP host adapter.
 *
 * The policy core and the adapter are intentionally independent of sing-box
 * and mihomo.  The caller owns XDP program attach/control and must publish an
 * XSKMAP entry only after sb_xdp_adapter_ready() is true.  A failed open,
 * poll, receive, recycle, or transmit must leave the TC path enabled.
 */
#ifndef SING_BOX_XDP_ENGINE_H
#define SING_BOX_XDP_ENGINE_H

#include <stdbool.h>
#include <stdint.h>

struct sb_xdp_adapter_config {
	uint32_t ifindex;
	uint32_t queue_count;
	uint32_t ring_size;
	uint32_t frame_size;
	uint32_t frame_count;
	uint32_t mode; /* 0 = XDP_ZEROCOPY, 1 = explicitly allowed XDP_COPY */
};

struct sb_xdp_frame {
	/* Queue that delivered the descriptor; shared-UMEM frames are not
	 * partition-owned and may be transmitted on another queue. */
	uint32_t queue;
	uint64_t address;
	uint32_t length;
	uint32_t options;
};

struct sb_xdp_adapter_stats {
	uint64_t rx;
	uint64_t tx;
	uint64_t recycled;
	uint64_t completed;
	uint64_t fill_starved;
	uint64_t tx_full;
	uint64_t invalid_descriptor;
};

struct sb_xdp_adapter;

/* Returns 1 for a real zero-copy bind, 2 for an explicitly requested copy
 * bind, and 0 when the interface/queue cannot create the requested XSK. */
uint32_t sb_xdp_adapter_probe_bind(
	const struct sb_xdp_adapter_config *config);
struct sb_xdp_adapter *sb_xdp_adapter_open(
	const struct sb_xdp_adapter_config *config);
int sb_xdp_adapter_queue_fd(const struct sb_xdp_adapter *adapter,
	uint32_t queue);
bool sb_xdp_adapter_ready(const struct sb_xdp_adapter *adapter);
int sb_xdp_adapter_poll(struct sb_xdp_adapter *adapter, int timeout_ms,
	uint64_t *ready_mask);
/* Returns 1 for a frame, 0 for no frame, and -1 for invalid input. */
int sb_xdp_adapter_rx(struct sb_xdp_adapter *adapter, uint32_t queue,
	struct sb_xdp_frame *frame);
/* Returns a borrowed pointer valid until the frame is recycled or queued for
 * TX. Multi-buffer descriptors are rejected and return NULL. */
uint8_t *sb_xdp_adapter_frame_data(struct sb_xdp_adapter *adapter,
	const struct sb_xdp_frame *frame, uint32_t *length);
int sb_xdp_adapter_recycle(struct sb_xdp_adapter *adapter,
	const struct sb_xdp_frame *frame);
int sb_xdp_adapter_tx(struct sb_xdp_adapter *adapter,
	const struct sb_xdp_frame *frame, uint32_t queue);
int sb_xdp_adapter_drain_completions(struct sb_xdp_adapter *adapter,
	uint32_t queue, uint32_t limit);
int sb_xdp_adapter_stats(const struct sb_xdp_adapter *adapter,
	struct sb_xdp_adapter_stats *stats);
void sb_xdp_adapter_close(struct sb_xdp_adapter *adapter);

#endif
