#!/usr/bin/env bash
# Fetch pinned build dependencies into third_party/.
#
#   scx      - sched_ext BPF headers (common.bpf.h, compat.bpf.h, UEI) and a
#              vmlinux.h with sched_ext types for x86 and arm64.
#   bpftool  - skeleton generator, with its libbpf submodule (built statically).
#
# Bump the pins deliberately: sched_ext kfuncs have no ABI guarantee (NFR-9).
set -euo pipefail

SCX_REPO=https://github.com/sched-ext/scx
SCX_COMMIT=d65d9ebf767de1f5e7245f1976580be1405673b3
BPFTOOL_REPO=https://github.com/libbpf/bpftool
BPFTOOL_TAG=v7.8.1

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TP="$ROOT/third_party"
JOBS="${JOBS:-$(nproc 2>/dev/null || echo 4)}"
mkdir -p "$TP"

retry() {
	local n=0 delay=2
	until "$@"; do
		n=$((n + 1))
		[ "$n" -ge 4 ] && return 1
		echo "retrying in ${delay}s: $*" >&2
		sleep "$delay"
		delay=$((delay * 2))
	done
}

fetch_scx() {
	local dst="$TP/scx"
	if [ -f "$dst/.commit" ] && [ "$(cat "$dst/.commit")" = "$SCX_COMMIT" ]; then
		echo "scx headers: up to date ($SCX_COMMIT)"
		return
	fi
	rm -rf "$dst" && mkdir -p "$dst"
	git -C "$dst" init -q
	git -C "$dst" remote add origin "$SCX_REPO"
	git -C "$dst" config core.sparseCheckout true
	printf '%s\n' scheds/include/ scheds/vmlinux/arch/x86/ scheds/vmlinux/arch/arm64/ \
		>"$dst/.git/info/sparse-checkout"
	retry git -C "$dst" fetch -q --depth 1 --filter=blob:none origin "$SCX_COMMIT"
	git -C "$dst" checkout -q FETCH_HEAD
	echo "$SCX_COMMIT" >"$dst/.commit"
	echo "scx headers: fetched $SCX_COMMIT"
}

fetch_bpftool() {
	local dst="$TP/bpftool"
	if [ -x "$dst/src/bpftool" ] && [ -f "$dst/src/libbpf/libbpf.a" ] &&
	   [ "$(cat "$dst/.tag" 2>/dev/null)" = "$BPFTOOL_TAG" ]; then
		echo "bpftool/libbpf: up to date ($BPFTOOL_TAG)"
		return
	fi
	rm -rf "$dst"
	retry git -c advice.detachedHead=false clone -q --depth 1 --branch "$BPFTOOL_TAG" --recurse-submodules \
		--shallow-submodules "$BPFTOOL_REPO" "$dst"
	# bpftool's build also produces a static libbpf.a and installs its headers
	# under src/libbpf/include, which hushd links against.
	make -s -C "$dst/src" -j"$JOBS" >/dev/null
	echo "$BPFTOOL_TAG" >"$dst/.tag"
	echo "bpftool/libbpf: built $BPFTOOL_TAG ($("$dst/src/bpftool" version | head -1))"
}

fetch_scx
fetch_bpftool
