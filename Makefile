# scx_hush build.
#
#   make deps      fetch pinned scx headers, build bpftool + static libbpf
#   make           BPF object, skeleton, hushd, libhush.so, tools
#   make bpf       BPF object and skeleton only
#   make test      C unit tests + pytest
#   make install   install to $(PREFIX) (default /usr/local)
#
# ARCH=x86|arm64 picks the BPF target and vmlinux.h. VMLINUX_H overrides the
# header; by default the host BTF is used when it carries sched_ext types,
# else the copy vendored by the scx project.

ARCH ?= $(shell uname -m | sed -e 's/x86_64/x86/' -e 's/aarch64/arm64/')
PREFIX ?= /usr/local
CC ?= cc
CLANG ?= clang
PYTHON ?= python3

ROOT := $(abspath .)
BUILD := $(ROOT)/build
TP := $(ROOT)/third_party
SCX_INC := $(TP)/scx/scheds/include
BPFTOOL_DIR := $(TP)/bpftool/src
BPFTOOL ?= $(BPFTOOL_DIR)/bpftool
LIBBPF_A := $(BPFTOOL_DIR)/libbpf/libbpf.a
LIBBPF_INC := $(BPFTOOL_DIR)/libbpf/include
TOML_DIR := $(TP)/tomlc99

VMLINUX_DIR := $(BUILD)/$(ARCH)
VMLINUX_H ?= $(VMLINUX_DIR)/vmlinux.h

BPF_CFLAGS := -g -O2 -target bpf -mcpu=v3 -D__TARGET_ARCH_$(ARCH) \
	-Wall -Wno-compare-distinct-pointer-types -Wno-unused-function \
	-I$(VMLINUX_DIR) -I$(SCX_INC) -I$(SCX_INC)/bpf-compat -I$(LIBBPF_INC) \
	-I$(ROOT)/include -I$(ROOT)/bpf

USER_CFLAGS := -O2 -g -Wall -Wextra -Wno-unused-parameter -Wno-sign-compare \
	-Wno-missing-field-initializers -D_GNU_SOURCE -std=gnu11 \
	-I$(BUILD) -I$(ROOT)/include -I$(ROOT)/hushd -I$(TOML_DIR) \
	-I$(LIBBPF_INC) -I$(SCX_INC)
USER_LDLIBS := $(LIBBPF_A) -lelf -lz -lpthread

HUSHD_SRCS := hushd/main.c hushd/policy.c hushd/cgroup.c hushd/ctl.c \
	hushd/json.c hushd/selftest.c hushd/util.c $(TOML_DIR)/toml.c
POLICY_SRCS := hushd/policy.c hushd/util.c $(TOML_DIR)/toml.c

.PHONY: all deps bpf hushd libhush tools test test-c test-py install clean distclean

all: bpf hushd libhush tools

deps:
	./scripts/fetch-deps.sh

$(LIBBPF_A) $(BPFTOOL):
	@echo "missing dependencies; run 'make deps' first" >&2; exit 1

# Prefer the running kernel's BTF when it has sched_ext; otherwise use the
# vendored vmlinux.h for $(ARCH).
$(VMLINUX_DIR)/vmlinux.h: | $(BPFTOOL)
	@mkdir -p $(VMLINUX_DIR)
	@if [ "$(ARCH)" = "$(shell uname -m | sed -e 's/x86_64/x86/' -e 's/aarch64/arm64/')" ] && \
	   [ -r /sys/kernel/btf/vmlinux ] && \
	   $(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format raw 2>/dev/null | \
	   grep -q "STRUCT 'sched_ext_ops'"; then \
		echo "  VMLINUX  host BTF"; \
		$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@; \
	else \
		echo "  VMLINUX  vendored ($(ARCH)); host kernel has no sched_ext BTF"; \
		cp $(TP)/scx/scheds/vmlinux/arch/$(ARCH)/vmlinux.h $@; \
	fi

bpf: $(BUILD)/scx_hush.bpf.o $(BUILD)/hush.skel.h

$(BUILD)/scx_hush.bpf.o: bpf/scx_hush.bpf.c bpf/hush_compat.bpf.h include/hush_intf.h $(VMLINUX_H)
	@mkdir -p $(BUILD)
	@echo "  CLANG    $@"
	$(Q)$(CLANG) $(BPF_CFLAGS) -c $< -o $@.tmp.o
	$(Q)$(BPFTOOL) gen object $@ $@.tmp.o
	@rm -f $@.tmp.o

$(BUILD)/hush.skel.h: $(BUILD)/scx_hush.bpf.o
	@echo "  SKEL     $@"
	$(Q)$(BPFTOOL) gen skeleton $< name scx_hush > $@

hushd: $(BUILD)/hushd

$(BUILD)/hushd: $(HUSHD_SRCS) hushd/*.h include/hush_intf.h $(BUILD)/hush.skel.h $(LIBBPF_A)
	@echo "  CC       $@"
	$(Q)$(CC) $(USER_CFLAGS) $(HUSHD_SRCS) -o $@ $(USER_LDLIBS)

libhush: $(BUILD)/libhush.so

$(BUILD)/libhush.so: libhush/libhush.c libhush/libhush.h
	@mkdir -p $(BUILD)
	@echo "  CC       $@"
	$(Q)$(CC) -O2 -g -Wall -fPIC -shared -fvisibility=hidden \
		-Wl,-soname,libhush.so.1 -Ilibhush $< -o $@
	@ln -sf libhush.so $(BUILD)/libhush.so.1

tools: $(BUILD)/tools/inversion_micro $(BUILD)/tools/periodic_loop

$(BUILD)/tools/inversion_micro: tools/inversion_micro.c $(BUILD)/libhush.so
	@mkdir -p $(BUILD)/tools
	@echo "  CC       $@"
	$(Q)$(CC) $(USER_CFLAGS) -Ilibhush $< -o $@ -L$(BUILD) -lhush \
		-Wl,-rpath,'$$ORIGIN/..' -lpthread

$(BUILD)/tools/periodic_loop: tools/periodic_loop.c
	@mkdir -p $(BUILD)/tools
	@echo "  CC       $@"
	$(Q)$(CC) $(USER_CFLAGS) $< -o $@ -lm

$(BUILD)/tests/test_policy: tests/c/test_policy.c $(POLICY_SRCS) hushd/policy.h
	@mkdir -p $(BUILD)/tests
	@echo "  CC       $@"
	$(Q)$(CC) $(USER_CFLAGS) $< $(POLICY_SRCS) -o $@

test: test-c test-py

test-c: $(BUILD)/tests/test_policy
	$(BUILD)/tests/test_policy $(ROOT)/tests/c/fixtures

test-py:
	$(PYTHON) -m pytest -q tests

install: all
	install -d $(DESTDIR)$(PREFIX)/sbin $(DESTDIR)$(PREFIX)/bin \
		$(DESTDIR)$(PREFIX)/lib $(DESTDIR)$(PREFIX)/include \
		$(DESTDIR)/etc/scx_hush
	install -m 0755 $(BUILD)/hushd $(DESTDIR)$(PREFIX)/sbin/hushd
	install -m 0755 cli/hushctl.py $(DESTDIR)$(PREFIX)/bin/hushctl
	install -m 0755 $(BUILD)/libhush.so $(DESTDIR)$(PREFIX)/lib/libhush.so.1
	ln -sf libhush.so.1 $(DESTDIR)$(PREFIX)/lib/libhush.so
	install -m 0644 libhush/libhush.h $(DESTDIR)$(PREFIX)/include/libhush.h
	[ -e $(DESTDIR)/etc/scx_hush/policy.toml ] || \
		install -m 0644 config/policy.toml $(DESTDIR)/etc/scx_hush/policy.toml

clean:
	rm -rf $(BUILD)

distclean: clean
	rm -rf $(TP)/scx $(TP)/bpftool

Q ?= @
