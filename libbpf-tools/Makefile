# SPDX-License-Identifier: GPL-2.0
# Copyright (c) 2025 Network Troubleshooting Tools Authors
# Makefile for libbpf-tools

CLANG ?= clang
LLC ?= llc
LLVM_STRIP ?= llvm-strip
BPFTOOL ?= bpftool
CC ?= gcc

# Directories
OUTPUT := output
TOOLS_DIR := tools
INCLUDE_DIR := include
LIB_DIR := lib
VMLINUX_DIR := vmlinux

# Kernel architecture detection
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

# Compiler flags
CFLAGS := -g -O2 -Wall -Wextra
LDFLAGS := -lelf -lz -lpthread

# BPF compiler flags
BPF_CFLAGS := -g -O2 \
	-target bpf \
	-D__TARGET_ARCH_$(ARCH) \
	-D__BPF__ \
	-I$(OUTPUT) \
	-I$(INCLUDE_DIR) \
	-I$(VMLINUX_DIR)

# Userspace compiler flags
USER_CFLAGS := $(CFLAGS) \
	-I$(OUTPUT) \
	-I$(INCLUDE_DIR) \
	-I$(LIB_DIR)

# Library source files
LIB_SRCS := $(wildcard $(LIB_DIR)/*.c)
LIB_OBJS := $(patsubst $(LIB_DIR)/%.c,$(OUTPUT)/%.o,$(LIB_SRCS))

# Tool list - add new tools here
TOOLS := \
	eth_drop \
	system_network_latency_summary \
	vm_network_latency_summary \
	kernel_icmp_rtt \
	ovs_upcall_latency_summary \
	kvm_irqfd_stats_summary \
	vhost_queue_correlation \
	virtnet_poll_monitor \
	vhost_buf_peek_stats

# Default target
.PHONY: all
all: $(OUTPUT) vmlinux.h $(addprefix $(OUTPUT)/,$(TOOLS))

# Create output directory
$(OUTPUT):
	mkdir -p $@

# Generate vmlinux.h from BTF
vmlinux.h: $(VMLINUX_DIR)/vmlinux.h

$(VMLINUX_DIR)/vmlinux.h:
	@if [ -f /sys/kernel/btf/vmlinux ]; then \
		echo "Generating vmlinux.h from /sys/kernel/btf/vmlinux..."; \
		$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@; \
	else \
		echo "ERROR: BTF not available at /sys/kernel/btf/vmlinux"; \
		echo "Please ensure your kernel has CONFIG_DEBUG_INFO_BTF=y"; \
		exit 1; \
	fi

# Build library object files
$(OUTPUT)/%.o: $(LIB_DIR)/%.c | $(OUTPUT)
	$(CC) $(USER_CFLAGS) -c $< -o $@

# Pattern rule for BPF objects
$(OUTPUT)/%.bpf.o: $(TOOLS_DIR)/%/%.bpf.c $(VMLINUX_DIR)/vmlinux.h | $(OUTPUT)
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@
	$(LLVM_STRIP) -g $@

# Pattern rule for skeletons
$(OUTPUT)/%.skel.h: $(OUTPUT)/%.bpf.o | $(OUTPUT)
	$(BPFTOOL) gen skeleton $< > $@

# Pattern rule for userspace binaries
# Dependencies: tool.c, tool.skel.h, library objects
$(OUTPUT)/%: $(TOOLS_DIR)/%/%.c $(OUTPUT)/%.skel.h $(LIB_OBJS) | $(OUTPUT)
	$(CC) $(USER_CFLAGS) \
		-I$(TOOLS_DIR)/$* \
		$< $(LIB_OBJS) \
		$(LDFLAGS) -lbpf -o $@

# Tool-specific dependencies
$(OUTPUT)/eth_drop: $(TOOLS_DIR)/eth_drop/eth_drop.c $(OUTPUT)/eth_drop.skel.h $(LIB_OBJS)
$(OUTPUT)/system_network_latency_summary: $(TOOLS_DIR)/system_network_latency_summary/system_network_latency_summary.c $(OUTPUT)/system_network_latency_summary.skel.h $(LIB_OBJS)
$(OUTPUT)/vm_network_latency_summary: $(TOOLS_DIR)/vm_network_latency_summary/vm_network_latency_summary.c $(OUTPUT)/vm_network_latency_summary.skel.h $(LIB_OBJS)
$(OUTPUT)/kernel_icmp_rtt: $(TOOLS_DIR)/kernel_icmp_rtt/kernel_icmp_rtt.c $(OUTPUT)/kernel_icmp_rtt.skel.h $(LIB_OBJS)
$(OUTPUT)/ovs_upcall_latency_summary: $(TOOLS_DIR)/ovs_upcall_latency_summary/ovs_upcall_latency_summary.c $(OUTPUT)/ovs_upcall_latency_summary.skel.h $(LIB_OBJS)
$(OUTPUT)/kvm_irqfd_stats_summary: $(TOOLS_DIR)/kvm_irqfd_stats_summary/kvm_irqfd_stats_summary.c $(OUTPUT)/kvm_irqfd_stats_summary.skel.h $(LIB_OBJS)
$(OUTPUT)/vhost_queue_correlation: $(TOOLS_DIR)/vhost_queue_correlation/vhost_queue_correlation.c $(OUTPUT)/vhost_queue_correlation.skel.h $(LIB_OBJS)
$(OUTPUT)/virtnet_poll_monitor: $(TOOLS_DIR)/virtnet_poll_monitor/virtnet_poll_monitor.c $(OUTPUT)/virtnet_poll_monitor.skel.h $(LIB_OBJS)
$(OUTPUT)/vhost_buf_peek_stats: $(TOOLS_DIR)/vhost_buf_peek_stats/vhost_buf_peek_stats.c $(OUTPUT)/vhost_buf_peek_stats.skel.h $(LIB_OBJS)

# Individual tool targets
.PHONY: eth_drop system_network_latency_summary vm_network_latency_summary kernel_icmp_rtt
.PHONY: ovs_upcall_latency_summary kvm_irqfd_stats_summary vhost_queue_correlation virtnet_poll_monitor vhost_buf_peek_stats

eth_drop: $(OUTPUT)/eth_drop
system_network_latency_summary: $(OUTPUT)/system_network_latency_summary
vm_network_latency_summary: $(OUTPUT)/vm_network_latency_summary
kernel_icmp_rtt: $(OUTPUT)/kernel_icmp_rtt
ovs_upcall_latency_summary: $(OUTPUT)/ovs_upcall_latency_summary
kvm_irqfd_stats_summary: $(OUTPUT)/kvm_irqfd_stats_summary
vhost_queue_correlation: $(OUTPUT)/vhost_queue_correlation
virtnet_poll_monitor: $(OUTPUT)/virtnet_poll_monitor
vhost_buf_peek_stats: $(OUTPUT)/vhost_buf_peek_stats

# Clean target
.PHONY: clean
clean:
	rm -rf $(OUTPUT)

# Deep clean - including vmlinux.h
.PHONY: distclean
distclean: clean
	rm -f $(VMLINUX_DIR)/vmlinux.h

# Help target
.PHONY: help
help:
	@echo "libbpf-tools build system"
	@echo ""
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@echo "  all                          - Build all tools"
	@echo "  <tool>                        - Build specific tool"
	@echo "  vmlinux.h                     - Generate vmlinux.h from BTF"
	@echo "  clean                         - Remove build artifacts"
	@echo "  distclean                     - Remove all generated files"
	@echo "  help                          - Show this help message"
	@echo ""
	@echo "Available tools:"
	@echo "  $(TOOLS)"
	@echo ""
	@echo "Environment variables:"
	@echo "  CLANG                         - Clang compiler (default: clang)"
	@echo "  BPFTOOL                       - bpftool binary (default: bpftool)"
	@echo "  CC                            - C compiler (default: gcc)"

# Install target
.PHONY: install
install: all
	install -d $(DESTDIR)/usr/bin
	install -m 755 $(addprefix $(OUTPUT)/,$(TOOLS)) $(DESTDIR)/usr/bin/

# Phony targets for development
.PHONY: check-deps
check-deps:
	@echo "Checking dependencies..."
	@which $(CLANG) > /dev/null 2>&1 || (echo "ERROR: clang not found"; exit 1)
	@which $(BPFTOOL) > /dev/null 2>&1 || (echo "ERROR: bpftool not found"; exit 1)
	@which $(LLC) > /dev/null 2>&1 || (echo "WARNING: llc not found")
	@test -f /sys/kernel/btf/vmlinux || (echo "ERROR: BTF not available"; exit 1)
	@echo "All dependencies satisfied!"
