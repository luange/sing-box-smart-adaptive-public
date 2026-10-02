// Copyright 2026 sing-box smart-adaptive contributors
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Linux-only AF_XDP object/control lifecycle.  The packet-forwarding loop is
// intentionally outside this loader: a queue is only enabled after its XSK
// has been bound and userspace owns the RX/TX rings.  Any failure leaves TC
// as the live path.

#define _GNU_SOURCE

#include "singbox_ebpf.h"

#include "../v3/kern/abi.h"

#include <errno.h>
#include <linux/bpf.h>
#include <linux/if_link.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <unistd.h>

#ifndef BPF_F_NO_PREALLOC
#define BPF_F_NO_PREALLOC 1U
#endif
#ifndef BPF_LINK_CREATE
#define BPF_LINK_CREATE 28
#endif
#ifndef BPF_XDP
#define BPF_XDP 37
#endif
#ifndef XDP_FLAGS_UPDATE_IF_NOEXIST
#define XDP_FLAGS_UPDATE_IF_NOEXIST (1U << 0)
#endif
#ifndef XDP_ATTACHED_NONE
#define XDP_ATTACHED_NONE 0
#endif
#ifndef XDP_ATTACHED_DRV
#define XDP_ATTACHED_DRV 1
#endif
#ifndef XDP_ATTACHED_SKB
#define XDP_ATTACHED_SKB 2
#endif
#ifndef XDP_ATTACHED_HW
#define XDP_ATTACHED_HW 3
#endif
#ifndef XDP_FLAGS_SKB_MODE
#define XDP_FLAGS_SKB_MODE (1U << 1)
#endif
#ifndef XDP_FLAGS_DRV_MODE
#define XDP_FLAGS_DRV_MODE (1U << 2)
#endif
#ifndef XDP_FLAGS_HW_MODE
#define XDP_FLAGS_HW_MODE (1U << 3)
#endif
#ifndef XDP_FLAGS_REPLACE
#define XDP_FLAGS_REPLACE (1U << 4)
#endif
#ifndef IFLA_XDP_FD
#define IFLA_XDP_FD 1
#endif
#ifndef IFLA_XDP_FLAGS
#define IFLA_XDP_FLAGS 3
#endif
#ifndef IFLA_XDP_ATTACHED
#define IFLA_XDP_ATTACHED 2
#endif
#ifndef XDP_ATTACHED_NONE
#define XDP_ATTACHED_NONE 0
#define XDP_ATTACHED_DRV 1
#define XDP_ATTACHED_SKB 2
#define XDP_ATTACHED_HW 3
#define XDP_ATTACHED_MULTI 4
#endif
#ifndef NLA_F_NESTED
#define NLA_F_NESTED (1U << 15)
#endif
#ifndef NLA_ALIGNTO
#define NLA_ALIGNTO 4U
#endif
#ifndef NLA_ALIGN
#define NLA_ALIGN(length) (((length) + NLA_ALIGNTO - 1U) & ~(NLA_ALIGNTO - 1U))
#endif
#ifndef NLA_HDRLEN
#define NLA_HDRLEN ((int)NLA_ALIGN(sizeof(struct nlattr)))
#endif
#ifndef NLA_DATA
#define NLA_DATA(attribute) ((void *)((uint8_t *)(attribute) + NLA_HDRLEN))
#endif
#ifndef NLA_OK
#define NLA_OK(attribute, remaining) ((remaining) >= (int)sizeof(struct nlattr) && \
	(attribute)->nla_len >= sizeof(struct nlattr) && \
	(attribute)->nla_len <= (remaining))
#endif
#ifndef NLA_NEXT
#define NLA_NEXT(attribute, remaining) ((remaining) -= NLA_ALIGN((attribute)->nla_len), \
	(struct nlattr *)((uint8_t *)(attribute) + NLA_ALIGN((attribute)->nla_len)))
#endif

#ifndef __NR_bpf
#if defined(__aarch64__)
#define __NR_bpf 280
#elif defined(__arm__)
#define __NR_bpf 386
#elif defined(__i386__)
#define __NR_bpf 357
#elif defined(__x86_64__)
#define __NR_bpf 321
#endif
#endif

static long xdp_bpf_sys(enum bpf_cmd cmd, union bpf_attr *attr) {
	return syscall(__NR_bpf, cmd, attr, sizeof(*attr));
}

static int xdp_close_fd(int *fd) {
	if (fd == NULL || *fd < 0)
		return 0;
	int value = *fd;
	*fd = -1;
	return close(value);
}

static void xdp_init(struct sb_ebpf_xdp_runtime *runtime) {
	memset(runtime, 0, sizeof(*runtime));
	runtime->control_map_fd = -1;
	runtime->xsk_map_fd = -1;
	runtime->program_fd = -1;
	runtime->link_fd = -1;
}

static int xdp_map_update(int map_fd, const void *key, const void *value) {
	union bpf_attr attr;
	memset(&attr, 0, sizeof(attr));
	attr.map_fd = (uint32_t)map_fd;
	attr.key = (uint64_t)(uintptr_t)key;
	attr.value = (uint64_t)(uintptr_t)value;
	attr.flags = BPF_ANY;
	return (int)xdp_bpf_sys(BPF_MAP_UPDATE_ELEM, &attr);
}

static int xdp_map_delete(int map_fd, const void *key) {
	union bpf_attr attr;
	memset(&attr, 0, sizeof(attr));
	attr.map_fd = (uint32_t)map_fd;
	attr.key = (uint64_t)(uintptr_t)key;
	return (int)xdp_bpf_sys(BPF_MAP_DELETE_ELEM, &attr);
}

static void xdp_clear_all_xsk(struct sb_ebpf_xdp_runtime *runtime) {
	if (runtime == NULL || runtime->xsk_map_fd < 0)
		return;
	for (uint32_t queue = 0; queue < runtime->queue_count; queue++)
		(void)xdp_map_delete(runtime->xsk_map_fd, &queue);
	runtime->xsk_bound_mask = 0U;
}

static int xdp_link_create(uint32_t ifindex, int program_fd) {
	union bpf_attr attr;
	memset(&attr, 0, sizeof(attr));
	attr.link_create.prog_fd = (uint32_t)program_fd;
	attr.link_create.target_ifindex = ifindex;
	attr.link_create.attach_type = BPF_XDP;
	return (int)xdp_bpf_sys(BPF_LINK_CREATE, &attr);
}

static int xdp_addattr(struct nlmsghdr *message, size_t capacity, uint16_t type,
			       const void *data, size_t data_size) {
	size_t length = NLMSG_ALIGN(message->nlmsg_len) + NLA_ALIGN(NLA_HDRLEN + data_size);
	if (length > capacity || data_size > UINT16_MAX - NLA_HDRLEN) {
		errno = EMSGSIZE;
		return -1;
	}
	struct nlattr *attribute = (struct nlattr *)((uint8_t *)message + NLMSG_ALIGN(message->nlmsg_len));
	attribute->nla_type = type;
	attribute->nla_len = (uint16_t)(NLA_HDRLEN + data_size);
	memcpy((uint8_t *)attribute + NLA_HDRLEN, data, data_size);
	message->nlmsg_len = (uint32_t)length;
	return 0;
}

static int xdp_set_link_fd(uint32_t ifindex, int program_fd, uint32_t mode_flags) {
	struct {
		struct nlmsghdr header;
		struct ifinfomsg interface;
		uint8_t attributes[128];
	} request;
	memset(&request, 0, sizeof(request));
	request.header.nlmsg_len = NLMSG_LENGTH(sizeof(request.interface));
	request.header.nlmsg_type = RTM_SETLINK;
	request.header.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	request.header.nlmsg_seq = 1U;
	request.interface.ifi_family = AF_UNSPEC;
	request.interface.ifi_index = (int)ifindex;
	struct nlattr *nested = (struct nlattr *)((uint8_t *)&request + NLMSG_ALIGN(request.header.nlmsg_len));
	nested->nla_type = (uint16_t)(IFLA_XDP | NLA_F_NESTED);
	nested->nla_len = NLA_HDRLEN;
	request.header.nlmsg_len = NLMSG_ALIGN(request.header.nlmsg_len) + NLA_HDRLEN;
	int fd_value = program_fd;
	if (xdp_addattr(&request.header, sizeof(request), IFLA_XDP_FD, &fd_value, sizeof(fd_value)) != 0)
		return -1;
	if (xdp_addattr(&request.header, sizeof(request), IFLA_XDP_FLAGS, &mode_flags, sizeof(mode_flags)) != 0)
		return -1;
	/* Fix the nested length after adding children. */
	nested->nla_len = (uint16_t)(request.header.nlmsg_len - ((uint8_t *)nested - (uint8_t *)&request));
	int netlink = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
	if (netlink < 0)
		return -1;
	struct sockaddr_nl address = {.nl_family = AF_NETLINK};
	struct iovec vector = {.iov_base = &request, .iov_len = request.header.nlmsg_len};
	struct msghdr message = {.msg_name = &address, .msg_namelen = sizeof(address), .msg_iov = &vector, .msg_iovlen = 1};
	int result = (int)sendmsg(netlink, &message, 0);
	if (result >= 0) {
		uint8_t response[256];
		struct iovec receive_vector = {.iov_base = response, .iov_len = sizeof(response)};
		struct msghdr receive_message = {.msg_name = &address, .msg_namelen = sizeof(address),
			.msg_iov = &receive_vector, .msg_iovlen = 1};
		result = (int)recvmsg(netlink, &receive_message, 0);
		if (result >= 0) {
			struct nlmsghdr *ack = (struct nlmsghdr *)response;
			if (ack->nlmsg_len >= NLMSG_LENGTH(sizeof(struct nlmsgerr)) && ack->nlmsg_type == NLMSG_ERROR) {
				struct nlmsgerr *error = (struct nlmsgerr *)NLMSG_DATA(ack);
				if (error->error != 0) {
					errno = -error->error;
					result = -1;
				} else {
					result = 0;
				}
			} else {
				errno = EBADMSG;
				result = -1;
			}
		}
	}
	int saved_errno = errno;
	(void)close(netlink);
	errno = saved_errno;
	return result < 0 ? -1 : 0;
}

/* Return the kernel's actual XDP attach mode for an interface.  A successful
 * attach API call is not enough: a dispatcher or a driver may have selected a
 * different mode than requested.  The caller treats NONE and MULTI as an
 * admission failure so the AF_XDP path never runs on an unverified hook. */
static int xdp_get_attached_mode(uint32_t ifindex) {
	struct {
		struct nlmsghdr header;
		struct ifinfomsg interface;
	} request;
	memset(&request, 0, sizeof(request));
	request.header.nlmsg_len = NLMSG_LENGTH(sizeof(request.interface));
	request.header.nlmsg_type = RTM_GETLINK;
	request.header.nlmsg_flags = NLM_F_REQUEST;
	request.header.nlmsg_seq = 2U;
	request.interface.ifi_family = AF_UNSPEC;
	request.interface.ifi_index = (int)ifindex;
	int netlink = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
	if (netlink < 0)
		return -1;
	struct sockaddr_nl address = {.nl_family = AF_NETLINK};
	struct iovec vector = {.iov_base = &request, .iov_len = request.header.nlmsg_len};
	struct msghdr message = {.msg_name = &address, .msg_namelen = sizeof(address),
		.msg_iov = &vector, .msg_iovlen = 1};
	int result = (int)sendmsg(netlink, &message, 0);
	if (result < 0) {
		int saved_errno = errno;
		(void)close(netlink);
		errno = saved_errno;
		return -1;
	}
	uint8_t response[8192];
	for (;;) {
		struct iovec receive_vector = {.iov_base = response, .iov_len = sizeof(response)};
		struct msghdr receive_message = {.msg_name = &address, .msg_namelen = sizeof(address),
			.msg_iov = &receive_vector, .msg_iovlen = 1};
		result = (int)recvmsg(netlink, &receive_message, 0);
		if (result < 0) {
			int saved_errno = errno;
			(void)close(netlink);
			errno = saved_errno;
			return -1;
		}
		for (struct nlmsghdr *header = (struct nlmsghdr *)response;
		     NLMSG_OK(header, (unsigned int)result);
		     header = NLMSG_NEXT(header, result)) {
			if (header->nlmsg_type == NLMSG_DONE) {
				(void)close(netlink);
				return XDP_ATTACHED_NONE;
			}
			if (header->nlmsg_type == NLMSG_ERROR) {
				if (header->nlmsg_len < NLMSG_LENGTH(sizeof(struct nlmsgerr))) {
					(void)close(netlink);
					errno = EBADMSG;
					return -1;
				}
				struct nlmsgerr *error = (struct nlmsgerr *)NLMSG_DATA(header);
				if (error->error != 0) {
					(void)close(netlink);
					errno = -error->error;
					return -1;
				}
				continue;
			}
			if (header->nlmsg_type != RTM_NEWLINK || header->nlmsg_len < NLMSG_LENGTH(sizeof(struct ifinfomsg)))
				continue;
			int remaining = (int)header->nlmsg_len - NLMSG_LENGTH(sizeof(struct ifinfomsg));
			struct nlattr *attribute = (struct nlattr *)((uint8_t *)NLMSG_DATA(header) + NLMSG_ALIGN(sizeof(struct ifinfomsg)));
			while (NLA_OK(attribute, remaining)) {
				if ((attribute->nla_type & NLA_F_NESTED) == NLA_F_NESTED &&
				    (attribute->nla_type & ~NLA_F_NESTED) == IFLA_XDP) {
					int nested_remaining = (int)attribute->nla_len - NLA_HDRLEN;
					struct nlattr *nested = (struct nlattr *)NLA_DATA(attribute);
					while (NLA_OK(nested, nested_remaining)) {
						if ((nested->nla_type & ~NLA_F_NESTED) == IFLA_XDP_ATTACHED &&
						    nested->nla_len >= NLA_HDRLEN + (int)sizeof(uint8_t)) {
							int mode = *(uint8_t *)NLA_DATA(nested);
							(void)close(netlink);
							return mode;
						}
						nested = NLA_NEXT(nested, nested_remaining);
					}
				}
				attribute = NLA_NEXT(attribute, remaining);
			}
			(void)close(netlink);
			return XDP_ATTACHED_NONE;
		}
	}
}

static int xdp_expected_attached_mode(uint32_t mode) {
	if (mode == SB_EBPF_XDP_MODE_SKB)
		return XDP_ATTACHED_SKB;
	if (mode == SB_EBPF_XDP_MODE_NATIVE)
		return XDP_ATTACHED_DRV;
	if (mode == SB_EBPF_XDP_MODE_OFFLOAD)
		return XDP_ATTACHED_HW;
	return XDP_ATTACHED_NONE;
}

int sb_ebpf_xdp_prepare(
	const uint8_t *object,
	size_t object_size,
	const struct sb_ebpf_v3_runtime *v3,
	uint32_t max_queues,
	struct sb_ebpf_xdp_runtime *runtime) {
	if (object == NULL || object_size == 0U || v3 == NULL || runtime == NULL ||
	    v3->control_map_fd < 0 || max_queues == 0U) {
		errno = EINVAL;
		return -1;
	}
	if (max_queues > SB_XDP_MAX_QUEUES)
		max_queues = SB_XDP_MAX_QUEUES;
	xdp_init(runtime);
	runtime->queue_count = max_queues;
	runtime->control_map_fd = sb_ebpf_create_map(
		BPF_MAP_TYPE_ARRAY, sizeof(uint32_t), sizeof(struct sb_xdp_control), 1U, 0U);
	runtime->xsk_map_fd = sb_ebpf_create_map(
		BPF_MAP_TYPE_XSKMAP, sizeof(uint32_t), sizeof(uint32_t), max_queues, 0U);
	if (runtime->control_map_fd < 0 || runtime->xsk_map_fd < 0)
		goto fail;

	struct sb_ebpf_object_map_entry entries[20];
	struct sb_ebpf_object_map_table maps;
	size_t n = 0U;
	entries[n++] = (struct sb_ebpf_object_map_entry){"v3_control", v3->control_map_fd};
	entries[n++] = (struct sb_ebpf_object_map_entry){"v3_policy4_bank0", v3->policy4_bank0_fd};
	entries[n++] = (struct sb_ebpf_object_map_entry){"v3_policy4_bank1", v3->policy4_bank1_fd};
	entries[n++] = (struct sb_ebpf_object_map_entry){"v3_policy6_bank0", v3->policy6_bank0_fd};
	entries[n++] = (struct sb_ebpf_object_map_entry){"v3_policy6_bank1", v3->policy6_bank1_fd};
	entries[n++] = (struct sb_ebpf_object_map_entry){"v3_host4", v3->host4_map_fd};
	entries[n++] = (struct sb_ebpf_object_map_entry){"v3_host6", v3->host6_map_fd};
	entries[n++] = (struct sb_ebpf_object_map_entry){"v3_flow_verdict", v3->flow_map_fd};
	entries[n++] = (struct sb_ebpf_object_map_entry){"v3_dns_ip_hint", v3->dns_hint_map_fd};
	entries[n++] = (struct sb_ebpf_object_map_entry){"v3_dns_observe", v3->dns_observe_map_fd};
	entries[n++] = (struct sb_ebpf_object_map_entry){"v3_source_mac", v3->source_mac_map_fd};
	entries[n++] = (struct sb_ebpf_object_map_entry){"v3_redirect", v3->redirect_map_fd};
	entries[n++] = (struct sb_ebpf_object_map_entry){"v3_listener_sockets", v3->listener_map_fd};
	entries[n++] = (struct sb_ebpf_object_map_entry){"v3_stats", v3->stats_map_fd};
	entries[n++] = (struct sb_ebpf_object_map_entry){"v3_xdp_control", runtime->control_map_fd};
	entries[n++] = (struct sb_ebpf_object_map_entry){"v3_xsk_map", runtime->xsk_map_fd};
	maps.entries = entries;
	maps.count = n;
	runtime->program_fd = sb_ebpf_object_load_section(
		object, object_size, "xdp", "sb_v3_xdp_ingress", BPF_PROG_TYPE_XDP,
		(enum bpf_attach_type)0, &maps);
	if (runtime->program_fd < 0)
		goto fail;
	/* Disabled until attach and every selected queue has a bound XSK. */
	uint32_t zero = 0U;
	struct sb_xdp_control control = {};
	control.abi_version = SB_XDP_ABI_VERSION;
	control.queue_count = max_queues;
	if (xdp_map_update(runtime->control_map_fd, &zero, &control) != 0)
		goto fail;
	return 0;

fail: {
		int saved_errno = errno;
		(void)sb_ebpf_xdp_close(runtime);
		errno = saved_errno;
		return -1;
	}
}

int sb_ebpf_xdp_attach(struct sb_ebpf_xdp_runtime *runtime, uint32_t ifindex) {
	return sb_ebpf_xdp_attach_mode(runtime, ifindex, SB_EBPF_XDP_MODE_NATIVE);
}

int sb_ebpf_xdp_attach_mode(struct sb_ebpf_xdp_runtime *runtime, uint32_t ifindex, uint32_t mode) {
	if (runtime == NULL || runtime->program_fd < 0 || ifindex == 0U) {
		errno = EINVAL;
		return -1;
	}
	if (runtime->link_fd >= 0) {
		if (runtime->ifindex == ifindex)
			return 0;
		errno = EBUSY;
		return -1;
	}
	if (mode < SB_EBPF_XDP_MODE_SKB || mode > SB_EBPF_XDP_MODE_OFFLOAD) {
		errno = EINVAL;
		return -1;
	}
	/* This adapter is intentionally exclusive.  libxdp can coordinate
	 * multiple XDP programs through its dispatcher protocol, but our object is
	 * not a dispatcher component and must never replace an unrelated program.
	 * Check before the native BPF_LINK_CREATE path as well as the rtnetlink
	 * paths, whose UPDATE_IF_NOEXIST flag provides only an implicit guard. */
	int existing_mode = xdp_get_attached_mode(ifindex);
	if (existing_mode < 0)
		return -1;
	if (existing_mode != XDP_ATTACHED_NONE) {
		errno = EBUSY;
		return -1;
	}
	int link = -1;
	if (mode == SB_EBPF_XDP_MODE_NATIVE) {
		link = xdp_link_create(ifindex, runtime->program_fd);
		if (link < 0)
			return -1;
	} else {
		uint32_t mode_flags = XDP_FLAGS_UPDATE_IF_NOEXIST;
		if (mode == SB_EBPF_XDP_MODE_SKB)
			mode_flags |= XDP_FLAGS_SKB_MODE;
		else
			mode_flags |= XDP_FLAGS_HW_MODE;
		if (xdp_set_link_fd(ifindex, runtime->program_fd, mode_flags) != 0)
			return -1;
	}
	runtime->link_fd = link;
	runtime->ifindex = ifindex;
	runtime->mode = mode;
	int attached_mode = xdp_get_attached_mode(ifindex);
	if (attached_mode < 0 || attached_mode != xdp_expected_attached_mode(mode)) {
		int saved_errno = attached_mode < 0 ? errno : EPROTONOSUPPORT;
		(void)sb_ebpf_xdp_detach(runtime);
		errno = saved_errno;
		return -1;
	}
	return 0;
}

int sb_ebpf_xdp_probe_mode(struct sb_ebpf_xdp_runtime *runtime, uint32_t ifindex, uint32_t mode) {
	if (runtime == NULL) {
		errno = EINVAL;
		return -1;
	}
	if (sb_ebpf_xdp_attach_mode(runtime, ifindex, mode) != 0)
		return -1;
	int attach_errno = 0;
	if (sb_ebpf_xdp_detach(runtime) != 0)
		attach_errno = errno;
	if (attach_errno != 0) {
		errno = attach_errno;
		return -1;
	}
	return 0;
}

int sb_ebpf_xdp_detach(struct sb_ebpf_xdp_runtime *runtime) {
	if (runtime == NULL)
		return 0;
	int result = xdp_close_fd(&runtime->link_fd);
	if (runtime->ifindex != 0U && runtime->mode != SB_EBPF_XDP_MODE_NATIVE) {
		if (xdp_set_link_fd(runtime->ifindex, -1,
				      runtime->mode == SB_EBPF_XDP_MODE_SKB ? XDP_FLAGS_SKB_MODE : XDP_FLAGS_HW_MODE) != 0 && result == 0)
			result = -1;
	}
	runtime->ifindex = 0U;
	runtime->mode = 0U;
	/* A link change or failed probe must not leave queue FDs armed for a
	 * later attach.  The next attach has to republish every queue explicitly. */
	xdp_clear_all_xsk(runtime);
	/* A detached program must never leave redirect enabled. */
	(void)sb_ebpf_xdp_set_control(runtime, false, 0U, 0U, 0U, 0U, false, 0U);
	return result;
}

int sb_ebpf_xdp_set_control(
	struct sb_ebpf_xdp_runtime *runtime,
	bool enabled,
	uint32_t policy_generation,
	uint32_t active_bank,
	uint32_t queue_count,
	uint32_t max_frame_size,
	bool allow_multibuffer,
	uint64_t attached_since_ns) {
	if (runtime == NULL || runtime->control_map_fd < 0 || queue_count > runtime->queue_count) {
		errno = EINVAL;
		return -1;
	}
	if (enabled) {
		if (queue_count == 0U) {
			errno = EINVAL;
			return -1;
		}
		uint64_t required = queue_count == 64U ? UINT64_MAX : ((UINT64_C(1) << queue_count) - 1U);
		if ((runtime->xsk_bound_mask & required) != required) {
			/* Keep the XDP control map disabled until every selected queue has
			 * an XSKMAP entry.  This is a retryable readiness failure, not a
			 * process-fatal dataplane error. */
			errno = EAGAIN;
			return -1;
		}
		if (allow_multibuffer) {
			/* The current parser/adapter consumes one descriptor per frame.
			 * Never let a caller opt into RX scatter-gather until a bounded
			 * multi-segment implementation exists. */
			errno = ENOTSUP;
			return -1;
		}
	}
	uint32_t zero = 0U;
	struct sb_xdp_control control = {};
	control.abi_version = SB_XDP_ABI_VERSION;
	control.flags = enabled ? SB_XDP_CTRL_ENABLED : 0U;
	if (allow_multibuffer)
		control.flags |= SB_XDP_CTRL_ALLOW_MULTIBUFFER;
	control.policy_generation = policy_generation;
	control.active_bank = active_bank & 1U;
	control.queue_count = queue_count;
	control.max_frame_size = max_frame_size;
	control.attached_since_ns = attached_since_ns;
	return xdp_map_update(runtime->control_map_fd, &zero, &control);
}

int sb_ebpf_xdp_set_xsk(struct sb_ebpf_xdp_runtime *runtime, uint32_t queue, int xsk_fd) {
	if (runtime == NULL || runtime->xsk_map_fd < 0 || queue >= runtime->queue_count || xsk_fd < 0) {
		errno = EINVAL;
		return -1;
	}
	int result = xdp_map_update(runtime->xsk_map_fd, &queue, &xsk_fd);
	if (result == 0)
		runtime->xsk_bound_mask |= UINT64_C(1) << queue;
	return result;
}

int sb_ebpf_xdp_clear_xsk(struct sb_ebpf_xdp_runtime *runtime, uint32_t queue) {
	if (runtime == NULL || runtime->xsk_map_fd < 0 || queue >= runtime->queue_count) {
		errno = EINVAL;
		return -1;
	}
	int result = xdp_map_delete(runtime->xsk_map_fd, &queue);
	if (result == 0 || errno == ENOENT)
		runtime->xsk_bound_mask &= ~(UINT64_C(1) << queue);
	return result;
}

int sb_ebpf_xdp_close(struct sb_ebpf_xdp_runtime *runtime) {
	if (runtime == NULL)
		return 0;
	int result = 0;
	if (sb_ebpf_xdp_detach(runtime) != 0)
		result = -1;
	if (xdp_close_fd(&runtime->program_fd) != 0 && result == 0)
		result = -1;
	if (xdp_close_fd(&runtime->xsk_map_fd) != 0 && result == 0)
		result = -1;
	if (xdp_close_fd(&runtime->control_map_fd) != 0 && result == 0)
		result = -1;
	runtime->queue_count = 0U;
	runtime->xsk_bound_mask = 0U;
	return result;
}

/* ── Hardware capability probe (no data plane) ──────────────────────────
 * Loads a two-instruction XDP program (r0 = XDP_PASS; exit) and briefly
 * attaches it to the target interface in native and then skb mode, reading
 * back the effective attach mode through netlink. This answers "does this
 * kernel + driver support XDP at all, and in which mode?" without routing
 * any traffic through sing-box: the program passes every packet to the
 * stack exactly as an unattached interface would. */
int sb_ebpf_xdp_probe_hardware(uint32_t ifindex, int *native_ok, int *skb_ok) {
	if (ifindex == 0U || native_ok == NULL || skb_ok == NULL) {
		errno = EINVAL;
		return -1;
	}
	*native_ok = 0;
	*skb_ok = 0;

	/* struct bpf_insn r0 = 2 (XDP_PASS); exit; */
	static const struct {
		uint8_t code;
		uint8_t dst_reg : 4;
		uint8_t src_reg : 4;
		uint16_t off;
		int32_t imm;
	} program[] = {
		{0xb7, 0, 0, 0, 2}, /* BPF_ALU64 | BPF_MOV | BPF_K */
		{0x95, 0, 0, 0, 0}, /* BPF_JMP | BPF_EXIT */
	};
	union bpf_attr attr;
	memset(&attr, 0, sizeof(attr));
	attr.prog_type = BPF_PROG_TYPE_XDP;
	attr.insns = (uint64_t)(uintptr_t)program;
	attr.insn_cnt = 2;
	attr.license = (uint64_t)(uintptr_t)"GPL";
	int program_fd = (int)xdp_bpf_sys(BPF_PROG_LOAD, &attr);
	if (program_fd < 0)
		return -1; /* kernel without usable BPF/XDP syscall support */

	int probe_errno = 0;
	for (int attempt = 0; attempt < 2; ++attempt) {
		uint32_t mode_flags = attempt == 0 ? (uint32_t)XDP_FLAGS_DRV_MODE : (uint32_t)XDP_FLAGS_SKB_MODE;
		if (xdp_set_link_fd(ifindex, program_fd, mode_flags) == 0) {
			int attached = xdp_get_attached_mode(ifindex);
			if (attempt == 0)
				*native_ok = attached > 0;
			else
				*skb_ok = attached > 0;
			(void)xdp_set_link_fd(ifindex, -1, mode_flags);
		} else if (attempt == 0) {
			probe_errno = errno;
		}
	}
	if (xdp_close_fd(&program_fd) != 0 && probe_errno == 0)
		probe_errno = errno;
	if (probe_errno != 0) {
		errno = probe_errno;
		return -1;
	}
	return 0;
}
