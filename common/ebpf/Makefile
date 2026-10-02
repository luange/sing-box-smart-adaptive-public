BPF_CLANG ?= $(if $(strip $(ANDROID_NDK_HOME)),$(ANDROID_NDK_HOME)/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android35-clang,clang)
BPF_SYSTEM_INCLUDE ?= /usr/include
BPF_HOST_CC ?= cc
BPF_MULTIARCH ?= $(shell $(BPF_HOST_CC) -print-multiarch 2>/dev/null)
BPF_MULTIARCH_INCLUDE ?= $(BPF_SYSTEM_INCLUDE)/$(BPF_MULTIARCH)
BPF_CFLAGS ?= -target bpfel -mcpu=v1 -O2 -g -ffreestanding
BPF_READELF ?= readelf
BPF_INCLUDE_FLAGS := -Inative -I$(BPF_SYSTEM_INCLUDE)
ifneq (,$(wildcard $(BPF_MULTIARCH_INCLUDE)))
BPF_INCLUDE_FLAGS += -I$(BPF_MULTIARCH_INCLUDE)
endif

# Luan fuller eBPF stack (shared_network + splice + v3). Upstream cgroup not mixed.
SOURCES := native/shared_network.bpf.c native/shared_network_v2.bpf.c native/splice.bpf.c v3/kern/tc.bpf.c
OBJECTS := $(SOURCES:.c=.o)
XDP_SOURCE := v3/kern/xdp.bpf.c
XDP_OBJECT := $(XDP_SOURCE:.c=.o)
V2_PROVENANCE_INPUTS := Makefile native/shared_network_v2.bpf.c native/shared_network.h \
	native/dataplane_v2.h native/dataplane_v2_parser.h native/btf_map.h
V2_SOURCE_HASH := $(shell cat $(V2_PROVENANCE_INPUTS) | sha256sum | cut -d' ' -f1)
V3_PROVENANCE_INPUTS := Makefile v3/kern/tc.bpf.c v3/kern/abi.h v3/kern/parser.h v3/kern/policy_maps.h native/btf_map.h
V3_SOURCE_HASH := $(shell cat $(V3_PROVENANCE_INPUTS) | sha256sum | cut -d' ' -f1)
XDP_PROVENANCE_INPUTS := Makefile $(XDP_SOURCE) v3/kern/abi.h v3/kern/parser.h v3/kern/policy_maps.h v3/kern/xdp_policy_maps.h native/btf_map.h
XDP_SOURCE_HASH := $(shell cat $(XDP_PROVENANCE_INPUTS) | sha256sum | cut -d' ' -f1)
BPF_INCLUDE_FLAGS += -Iv3/kern

.PHONY: generate check check-v2-source check-v3-source xdp-generate xdp-check check-xdp-source clean

generate:
	@set -eu; \
	for src in $(SOURCES); do \
		obj="$${src%.c}.o"; \
		temporary="$$(mktemp "$${obj}.XXXXXX")"; \
		trap 'rm -f "$$temporary"' EXIT; \
		extra_flags=""; \
		if [ "$$src" = native/shared_network_v2.bpf.c ]; then \
			extra_flags='-DSB_SOURCE_HASH="$(V2_SOURCE_HASH)"'; \
		fi; \
		if [ "$$src" = v3/kern/tc.bpf.c ]; then \
			extra_flags='-DSB_V3_SOURCE_HASH="$(V3_SOURCE_HASH)"'; \
		fi; \
		$(BPF_CLANG) $(BPF_CFLAGS) $(BPF_INCLUDE_FLAGS) $$extra_flags -c "$$src" -o "$$temporary"; \
		mv "$$temporary" "$$obj"; \
		trap - EXIT; \
	done

check:
	@set -eu; \
	for src in $(SOURCES); do \
		obj="$${src%.c}.o"; \
		if [ ! -f "$$obj" ]; then echo "$$obj missing" >&2; exit 1; fi; \
		temporary="$$(mktemp "$${obj}.XXXXXX")"; \
		trap 'rm -f "$$temporary"' EXIT; \
		extra_flags=""; \
		if [ "$$src" = native/shared_network_v2.bpf.c ]; then \
			extra_flags='-DSB_SOURCE_HASH="$(V2_SOURCE_HASH)"'; \
		fi; \
		if [ "$$src" = v3/kern/tc.bpf.c ]; then \
			extra_flags='-DSB_V3_SOURCE_HASH="$(V3_SOURCE_HASH)"'; \
		fi; \
		$(BPF_CLANG) $(BPF_CFLAGS) $(BPF_INCLUDE_FLAGS) $$extra_flags -c "$$src" -o "$$temporary"; \
		if ! cmp -s "$$obj" "$$temporary"; then echo "$$obj stale" >&2; exit 1; fi; \
		rm -f "$$temporary"; \
		trap - EXIT; \
	done

check-v2-source:
	@set -eu; \
	actual="$$($(BPF_READELF) -p .sb.source native/shared_network_v2.bpf.o 2>/dev/null \
		| sed -n 's/.*\]  \([0-9a-f]\{64\}\).*/\1/p')"; \
	if [ "$$actual" != "$(V2_SOURCE_HASH)" ]; then \
		echo "native/shared_network_v2.bpf.o source provenance stale" >&2; \
		echo "embedded=$$actual expected=$(V2_SOURCE_HASH)" >&2; \
		exit 1; \
	fi

check-v3-source:
	@set -eu; \
	actual="$$($(BPF_READELF) -p .sb.source v3/kern/tc.bpf.o 2>/dev/null \
		| sed -n 's/.*]  \([0-9a-f]\{64\}\).*/\1/p')"; \
	if [ "$$actual" != "$(V3_SOURCE_HASH)" ]; then \
		echo "v3/kern/tc.bpf.o source provenance stale" >&2; \
		echo "embedded=$$actual expected=$(V3_SOURCE_HASH)" >&2; \
		exit 1; \
	fi

# XDP is deliberately a separate target: the object is never embedded into
# the Go TC path and cannot silently enable AF_XDP on a production gateway.
xdp-generate:
	@set -eu; \
	temporary="$$(mktemp "$(XDP_OBJECT).XXXXXX")"; \
	trap 'rm -f "$$temporary"' EXIT; \
	extra_flags='-DSB_XDP_SOURCE_HASH="$(XDP_SOURCE_HASH)"'; \
	$(BPF_CLANG) $(BPF_CFLAGS) $(BPF_INCLUDE_FLAGS) $$extra_flags -c "$(XDP_SOURCE)" -o "$$temporary"; \
	mv "$$temporary" "$(XDP_OBJECT)"; \
	trap - EXIT

xdp-check:
	@set -eu; \
	if [ ! -f "$(XDP_OBJECT)" ]; then echo "$(XDP_OBJECT) missing" >&2; exit 1; fi; \
	temporary="$$(mktemp "$(XDP_OBJECT).XXXXXX")"; \
	trap 'rm -f "$$temporary"' EXIT; \
	extra_flags='-DSB_XDP_SOURCE_HASH="$(XDP_SOURCE_HASH)"'; \
	$(BPF_CLANG) $(BPF_CFLAGS) $(BPF_INCLUDE_FLAGS) $$extra_flags -c "$(XDP_SOURCE)" -o "$$temporary"; \
	cmp -s "$(XDP_OBJECT)" "$$temporary" || { echo "$(XDP_OBJECT) stale" >&2; exit 1; }; \
	rm -f "$$temporary"; trap - EXIT

check-xdp-source:
	@set -eu; \
	actual="$$($(BPF_READELF) -p .sb.source "$(XDP_OBJECT)" 2>/dev/null | sed -n 's/.*]  \([0-9a-f]\{64\}\).*/\1/p')"; \
	if [ "$$actual" != "$(XDP_SOURCE_HASH)" ]; then \
		echo "$(XDP_OBJECT) source provenance stale" >&2; \
		echo "embedded=$$actual expected=$(XDP_SOURCE_HASH)" >&2; \
		exit 1; \
	fi

clean:
	rm -f $(OBJECTS) $(XDP_OBJECT)
