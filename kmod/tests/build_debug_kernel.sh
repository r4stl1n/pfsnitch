#!/bin/sh
# build_debug_kernel.sh - build and install a GENERIC-DEBUG kernel, and rebuild
# mac_pfsnitch.ko to match it, so the stress/fuzz harnesses run under a kernel
# that actually catches the bugs a module like this can hide.
#
# Stock RELEASE ships GENERIC: no INVARIANTS, no WITNESS. A use-after-free or a
# lock-order reversal in the module is then invisible until it happens to fault.
# GENERIC-DEBUG turns on:
#   INVARIANTS/INVARIANT_SUPPORT - malloc/UMA poison freed memory and assert on
#                                  reuse, so a UAF of a label becomes a panic
#                                  AT the bug, not pages later;
#   WITNESS                      - every lock acquisition is checked for order,
#                                  so a lock-order reversal is reported the
#                                  first time it is even possible, not only when
#                                  it deadlocks;
#   DEADLKRES                    - a stuck lock is detected and reported;
#   QUEUE_MACRO_DEBUG_TRASH      - queue(9) pointers are trashed on removal, so
#                                  a stale reference through the module's label
#                                  list is caught immediately.
#
# KBI matters: a module built without these options must NOT be loaded into a
# kernel built with them - the struct layouts differ. So step 2 rebuilds the
# module against the debug kernel's own option headers (KERNBUILDDIR), which is
# the supported way to match an out-of-tree module to a specific kernel.
#
# Recovery if the debug kernel misbehaves: the installer keeps the old kernel in
# /boot/kernel.old; at the loader prompt, `boot kernel.old`. (And on a VM, a
# pre-build snapshot is the fastest way back.)
#
#   doas sh build_debug_kernel.sh build     # buildkernel (long; run detached)
#   doas sh build_debug_kernel.sh install   # installkernel + rebuild module
#   # reboot, then: kldload mac_pfsnitch && doas sh run.sh
set -eu

KERNCONF=GENERIC-DEBUG
SRC=/usr/src
ARCH=$(uname -m)
OBJ="/usr/obj${SRC}/${ARCH}.$(uname -p)/sys/${KERNCONF}"
KMOD_DIR=$(cd "$(dirname "$0")/.." && pwd)

case "${1:-}" in
build)
	echo "buildkernel ${KERNCONF} (this takes a while)..."
	cd "$SRC"
	# -j2 suits a small VM; drop to -j1 if the build is OOM-killed.
	make -j2 buildkernel KERNCONF="$KERNCONF"
	echo "buildkernel done. Next: doas sh $0 install"
	;;
install)
	echo "installkernel ${KERNCONF} (old kernel -> /boot/kernel.old)..."
	cd "$SRC"
	make installkernel KERNCONF="$KERNCONF"
	echo "rebuilding mac_pfsnitch.ko against the debug kernel (KBI match)..."
	[ -d "$OBJ" ] || { echo "no kernel build dir $OBJ - run build first" >&2; exit 1; }
	cd "$KMOD_DIR"
	make clean >/dev/null 2>&1 || true
	make KERNBUILDDIR="$OBJ"
	echo
	echo "Installed. Reboot into the debug kernel, then:"
	echo "  kldload $KMOD_DIR/mac_pfsnitch.ko"
	echo "  doas sh $KMOD_DIR/tests/run.sh"
	echo "A WITNESS/INVARIANTS kernel runs slower - that is expected."
	;;
*)
	echo "usage: doas sh $0 build|install" >&2
	exit 2
	;;
esac
