#!/bin/sh
# run.sh - drive the mac_pfsnitch stress and fuzz harnesses, and judge the
# result the way a kernel module has to be judged: not just "did it return 0"
# but "did the kernel stay healthy, and did it leak".
#
# Checks, in order:
#   1. the module is loaded and /dev/pfsnitch is present;
#   2. capture the malloc-accounting baseline (vmstat -m) and a dmesg mark;
#   3. run the ioctl fuzzer (single- and multi-threaded);
#   4. run the concurrency stress harness;
#   5. LEAK: the pfsnitch malloc type must return to ~baseline once idle -
#      every label allocated at socket_create must have been freed at destroy;
#   6. HEALTH: dmesg must show no new panic/fault/lock-order/leak lines.
#
# Run as root (needs to read the socket labels and the message buffer):
#   doas ./run.sh [-q quick]
#
# A debug kernel (INVARIANTS+WITNESS) makes steps 5-6 far sharper; see
# build_debug_kernel.sh. On GENERIC this still catches gross faults, hangs,
# and leaks.
set -u

cd "$(dirname "$0")"
QUICK=0
[ "${1:-}" = "-q" ] && QUICK=1

fail() { printf '\n\033[31mFAIL:\033[0m %s\n' "$1"; exit 1; }
ok()   { printf '\033[32mok:\033[0m %s\n' "$1"; }

# 1. preconditions -----------------------------------------------------------
kldstat -q -m mac_pfsnitch || fail "mac_pfsnitch not loaded (kldload mac_pfsnitch)"
[ -c /dev/pfsnitch ] || fail "/dev/pfsnitch missing"
[ "$(id -u)" = 0 ] || fail "run me as root (doas ./run.sh)"
ok "module loaded, device present"

# build the harnesses
cc -O2 -pthread -o fuzz_ioctl fuzz_ioctl.c || fail "build fuzz_ioctl"
cc -O2 -pthread -o stress stress.c || fail "build stress"
ok "harnesses built"

# 2. baseline ----------------------------------------------------------------
pfsn_inuse() { vmstat -m | awk '$1=="pfsnitch"{print $2; found=1} END{if(!found)print 0}'; }
BASE_INUSE=$(pfsn_inuse)
DMESG_BEFORE=$(mktemp /tmp/pfsn.dmesg.XXXXXX)
dmesg > "$DMESG_BEFORE"
printf 'baseline: pfsnitch live allocations = %s\n' "$BASE_INUSE"

if [ "$QUICK" = 1 ]; then
	FUZZ_N=50000; FUZZ_T=4; ST_D=8; ST_C=6; ST_Q=4; ST_F=2
else
	FUZZ_N=400000; FUZZ_T=8; ST_D=45; ST_C=8; ST_Q=6; ST_F=3
fi

# 3. fuzz --------------------------------------------------------------------
printf '\n--- ioctl fuzz (single thread, deterministic) ---\n'
./fuzz_ioctl -n "$FUZZ_N" -t 1 -s 1 || fail "fuzz_ioctl single-thread invariant violation"
printf '\n--- ioctl fuzz (%d threads) ---\n' "$FUZZ_T"
./fuzz_ioctl -n "$FUZZ_N" -t "$FUZZ_T" -s 12345 || fail "fuzz_ioctl multi-thread invariant violation"
ok "fuzz clean"

# 4. stress ------------------------------------------------------------------
printf '\n--- concurrency stress ---\n'
./stress -d "$ST_D" -c "$ST_C" -q "$ST_Q" -f "$ST_F" || fail "stress reported invariant violations"
ok "stress clean"

# 5. leak --------------------------------------------------------------------
# A label is freed at socket_destroy, but a socket does not die the instant its
# fd closes - loopback connections pass through closing states first. So the
# test is not "is the count low now" but "does it DRAIN back to baseline": a
# real leak stays elevated forever, TIME_WAIT retention decays away. Poll until
# it returns near baseline, or fail if it plateaus high.
# A leak is a PLATEAU, not a slow drain. A big run leaves a large backlog of
# sockets in closing states, and on a WITNESS/INVARIANTS kernel they are freed
# slowly - so a fixed deadline would falsely accuse a drain that is plainly
# working. Instead: keep waiting as long as the count keeps falling, and only
# fail if it STOPS falling while still well above baseline. That tells a real
# leak (stuck) apart from deferred frees (still decreasing) regardless of rate.
printf '\ndraining (label frees are deferred past fd close; watching for plateau)\n'
# A real leak never returns to baseline: the count stops improving and stays
# there. A slow drain keeps setting new lows, just unevenly (TIME_WAIT expires
# in bursts). So track the best (lowest) count seen and only cry leak after a
# sustained stretch with NO improvement on it - which a live drain never
# produces, but a leak does immediately.
TOL=64
BEST=$(pfsn_inuse)
STALL=0
DRAINED=0
i=0
while [ "$i" -lt 240 ]; do
	sleep 3; i=$((i+3))
	AFTER_INUSE=$(pfsn_inuse)
	DELTA=$((AFTER_INUSE - BASE_INUSE))
	printf '  t+%-3ss  live=%-7s  delta=%s\n' "$i" "$AFTER_INUSE" "$DELTA"
	if [ "$DELTA" -le "$TOL" ]; then DRAINED=1; break; fi
	if [ "$AFTER_INUSE" -lt "$BEST" ]; then
		BEST=$AFTER_INUSE			# still draining
		STALL=0
	else
		STALL=$((STALL + 1))
		# 30s with no new low, still well above baseline: the frees have
		# genuinely stopped while allocations remain - that is a leak.
		[ "$STALL" -ge 10 ] && fail "label leak: no new low for 30s at $DELTA above baseline (was $BASE_INUSE, now $AFTER_INUSE)"
	fi
done
[ "$DRAINED" = 1 ] || fail "label allocations did not return to baseline within 240s (still $DELTA above)"
ok "no leak: drained to within $DELTA of baseline"

# 6. health ------------------------------------------------------------------
DMESG_AFTER=$(mktemp /tmp/pfsn.dmesg.XXXXXX)
dmesg > "$DMESG_AFTER"
NEW=$(diff "$DMESG_BEFORE" "$DMESG_AFTER" | grep '^>' | sed 's/^> //')
rm -f "$DMESG_BEFORE" "$DMESG_AFTER"
if [ -n "$NEW" ]; then
	# A fault or corruption is fatal whatever caused it.
	FATAL=$(printf '%s\n' "$NEW" | grep -iE 'panic|fatal trap|page fault|use-after|leaked|memory modified|corrupt|Trashed' || true)
	if [ -n "$FATAL" ]; then
		printf '%s\n' "$FATAL"
		fail "kernel reported memory corruption or a fault during the run"
	fi
	# Lock-order reversals: only OURS are a bug. This module's lock is named
	# "pfsnitch", so a LOR that implicates us mentions it; unrelated
	# infrastructure LORs (e.g. the known vtnet0-rx0 -> in6_multi_sx in the
	# virtio-net path) are background noise on a WITNESS kernel and must not
	# fail our test. Flag a reversal only when pfsnitch appears among the
	# newly-printed WITNESS lines.
	LOR=$(printf '%s\n' "$NEW" | grep -iE 'lock order|witness' || true)
	if [ -n "$LOR" ]; then
		if printf '%s\n' "$NEW" | grep -qi 'pfsnitch'; then
			printf '%s\n' "$LOR"
			fail "a lock-order reversal implicating pfsnitch appeared"
		fi
		printf 'note: unrelated WITNESS lines (not pfsnitch), treated as benign:\n'
		printf '%s\n' "$LOR" | sed 's/^/  /'
	fi
fi
ok "no fault / corruption / pfsnitch lock-order reversal in dmesg"

printf '\n\033[32mALL CHECKS PASSED\033[0m\n'
