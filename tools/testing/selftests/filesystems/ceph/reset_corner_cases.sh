#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# CephFS client reset corner case tests.
# Runs a checklist of targeted tests that exercise specific reset
# code paths not covered by the stress tests.
#
# Requires: mounted CephFS, debugfs access (root), flock(1) utility.

set -uo pipefail

KSFT_SKIP=4

# kselftest auto-detect: when invoked with no arguments (e.g. by
# "make run_tests"), find a CephFS mount automatically or skip.
if [[ $# -eq 0 ]]; then
	MOUNT_POINT="$(findmnt -t ceph -n -o TARGET 2>/dev/null | head -1)"
	if [[ -z "$MOUNT_POINT" ]]; then
		echo "SKIP: No CephFS mount found and --mount-point not specified"
		exit "$KSFT_SKIP"
	fi
	exec "$0" --mount-point "$MOUNT_POINT"
fi

MOUNT_POINT=""
DEBUGFS_ROOT="/sys/kernel/debug/ceph"
DEBUGFS_CLIENT=""
TRIGGER_PATH=""
STATUS_PATH=""
TEMP_MNT=""

PASS_COUNT=0
FAIL_COUNT=0
SKIP_COUNT=0
TOTAL=4

log()
{
	printf '[%s] %s\n' "$(date -u +%H:%M:%S)" "$1"
}

result()
{
	local num="$1"
	local name="$2"
	local status="$3"
	local detail="${4:-}"

	case "$status" in
	PASS) PASS_COUNT=$((PASS_COUNT + 1)) ;;
	FAIL) FAIL_COUNT=$((FAIL_COUNT + 1)) ;;
	SKIP) SKIP_COUNT=$((SKIP_COUNT + 1)) ;;
	esac

	if [[ -n "$detail" ]]; then
		printf '[%d/%d] %-30s %s  (%s)\n' "$num" "$TOTAL" "$name" "$status" "$detail"
	else
		printf '[%d/%d] %-30s %s\n' "$num" "$TOTAL" "$name" "$status"
	fi
}

read_status_field()
{
	local field="$1"
	awk -F': ' -v key="$field" '$1 == key {print $2}' "$STATUS_PATH" 2>/dev/null
}

wait_reset_done()
{
	local timeout="${1:-30}"
	local elapsed=0

	while [[ "$(read_status_field "phase")" != "idle" ]]; do
		sleep 1
		elapsed=$((elapsed + 1))
		if [[ "$elapsed" -ge "$timeout" ]]; then
			return 1
		fi
	done
	return 0
}

list_reset_clients()
{
	local entry

	for entry in "$DEBUGFS_ROOT"/*/; do
		entry="$(basename "$entry")"
		[[ -d "$DEBUGFS_ROOT/$entry/reset" ]] || continue
		[[ -w "$DEBUGFS_ROOT/$entry/reset/trigger" ]] || continue
		printf '%s\n' "$entry"
	done
}

wait_status_nonidle()
{
	local status_path="$1"
	local timeout="${2:-10}"
	local polls=$((timeout * 10))
	local phase

	while [[ "$polls" -gt 0 ]]; do
		phase="$(awk -F': ' '$1 == "phase" {print $2}' "$status_path" 2>/dev/null)"
		if [[ -n "$phase" && "$phase" != "idle" ]]; then
			return 0
		fi
		sleep 0.1
		polls=$((polls - 1))
	done

	return 1
}

discover_debugfs()
{
	local candidates=()
	local entry

	if [[ -n "$DEBUGFS_CLIENT" ]]; then
		if [[ ! -d "$DEBUGFS_ROOT/$DEBUGFS_CLIENT/reset" ]]; then
			echo "SKIP: reset debugfs not found for $DEBUGFS_CLIENT" >&2
			exit "$KSFT_SKIP"
		fi
		return 0
	fi

	for entry in "$DEBUGFS_ROOT"/*/; do
		entry="$(basename "$entry")"
		[[ -d "$DEBUGFS_ROOT/$entry/reset" ]] || continue
		[[ -w "$DEBUGFS_ROOT/$entry/reset/trigger" ]] || continue
		candidates+=("$entry")
	done

	if [[ ${#candidates[@]} -eq 0 ]]; then
		echo "SKIP: No writable Ceph reset interface found under $DEBUGFS_ROOT" >&2
		exit "$KSFT_SKIP"
	fi

	if [[ ${#candidates[@]} -gt 1 ]]; then
		echo "SKIP: Multiple Ceph clients found: ${candidates[*]}. Use --client-id." >&2
		exit "$KSFT_SKIP"
	fi

	DEBUGFS_CLIENT="${candidates[0]}"
}

# --- Test 1: ebusy_rejection ------------------------------------------------
#
# Trigger a reset while another is guaranteed in-flight.  Creates
# dirty state so the first reset enters DRAINING (which takes
# measurable time), then polls until phase != idle and issues the
# second trigger.  The second trigger must fail (the kernel returns
# -EBUSY), and only one reset must be counted in the accounting.

test_ebusy_rejection()
{
	local num=1
	local name="ebusy_rejection"
	local testfile="$MOUNT_POINT/.reset_corner_ebusy_$$"
	local tc_before tc_after sc_before sc_after second_rc phase elapsed

	tc_before="$(read_status_field "trigger_count")"
	sc_before="$(read_status_field "success_count")"

	# Create dirty state so the first reset enters DRAINING
	echo "ebusy_dirty_data" > "$testfile"
	sync "$testfile"

	python3 -c "
import os, sys
fd = os.open('$testfile', os.O_WRONLY | os.O_APPEND)
os.write(fd, b'dirty_for_ebusy_test\n')
sys.stdout.write('written')
" 2>/dev/null || {
		result "$num" "$name" FAIL "dirty write failed"
		rm -f "$testfile"
		return
	}

	# Trigger the first reset -- it will drain dirty state
	echo "ebusy_first" > "$TRIGGER_PATH" 2>/dev/null || {
		result "$num" "$name" FAIL "first trigger failed"
		rm -f "$testfile"
		return
	}

	# Poll until phase is non-idle (quiescing or draining)
	elapsed=0
	while true; do
		phase="$(read_status_field "phase")"
		if [[ "$phase" != "idle" ]]; then
			break
		fi
		sleep 0.1
		elapsed=$((elapsed + 1))
		if [[ "$elapsed" -ge 50 ]]; then
			result "$num" "$name" SKIP \
				"first reset completed before overlap could be tested"
			rm -f "$testfile" 2>/dev/null
			return
		fi
	done

	# Issue the second trigger -- should be rejected with EBUSY
	second_rc=0
	echo "ebusy_second" > "$TRIGGER_PATH" 2>/dev/null && second_rc=0 || second_rc=$?

	if ! wait_reset_done 30; then
		result "$num" "$name" FAIL "first reset never completed"
		rm -f "$testfile"
		return
	fi

	tc_after="$(read_status_field "trigger_count")"
	sc_after="$(read_status_field "success_count")"

	if [[ "$((tc_after - tc_before))" -ne 1 ]]; then
		result "$num" "$name" FAIL "trigger_count +$((tc_after - tc_before)), expected +1"
		rm -f "$testfile"
		return
	fi

	if [[ "$((sc_after - sc_before))" -ne 1 ]]; then
		result "$num" "$name" FAIL "success_count +$((sc_after - sc_before)), expected +1"
		rm -f "$testfile"
		return
	fi

	if [[ "$second_rc" -eq 0 ]]; then
		result "$num" "$name" FAIL "second trigger did not return error"
		rm -f "$testfile"
		return
	fi

	rm -f "$testfile" 2>/dev/null
	result "$num" "$name" PASS
}

# --- Test 2: dirty_caps_at_reset --------------------------------------------
#
# Write to a file without fsync (dirty caps), trigger reset, then
# verify the file is not corrupt.  Manual reset drains dirty caps
# before teardown (best-effort, 5s timeout).  For a non-stuck cap
# the dirty write should be flushed during drain and persist.
# If the drain window is too short, only the synced first line
# persists -- that is acceptable (data loss is documented for
# unflushed writes).

test_dirty_caps_at_reset()
{
	local num=2
	local name="dirty_caps_at_reset"
	local testfile="$MOUNT_POINT/.reset_corner_dirty_caps_$$"
	local content_after line_count sc_before sc_after le

	sc_before="$(read_status_field "success_count")"

	echo "line_1_before_dirty_write" > "$testfile"
	sync "$testfile"

	python3 -c "
import os, sys
fd = os.open('$testfile', os.O_WRONLY | os.O_APPEND)
os.write(fd, b'line_2_dirty_no_fsync\n')
# deliberately no fsync -- leave caps dirty
sys.stdout.write('written')
" 2>/dev/null || {
		result "$num" "$name" FAIL "dirty write failed"
		rm -f "$testfile"
		return
	}

	echo "dirty_caps_test" > "$TRIGGER_PATH" 2>/dev/null || {
		result "$num" "$name" FAIL "reset trigger failed"
		rm -f "$testfile"
		return
	}

	if ! wait_reset_done 30; then
		result "$num" "$name" FAIL "reset did not complete"
		rm -f "$testfile"
		return
	fi

	sc_after="$(read_status_field "success_count")"
	if [[ "$sc_after" -le "$sc_before" ]]; then
		result "$num" "$name" FAIL "success_count did not increment (reset not exercised)"
		rm -f "$testfile"
		return
	fi

	sync "$testfile" 2>/dev/null || true
	content_after="$(cat "$testfile" 2>/dev/null)" || {
		result "$num" "$name" FAIL "cannot read file after reset"
		rm -f "$testfile"
		return
	}

	if [[ -z "$content_after" ]]; then
		result "$num" "$name" FAIL "file is empty after reset"
		rm -f "$testfile"
		return
	fi

	line_count="$(echo "$content_after" | wc -l)"
	if [[ "$line_count" -lt 1 ]]; then
		result "$num" "$name" FAIL "file has $line_count lines, expected >= 1"
		rm -f "$testfile"
		return
	fi

	echo "$content_after" | head -1 | grep -q "line_1_before_dirty_write" || {
		result "$num" "$name" FAIL "first line corrupted"
		rm -f "$testfile"
		return
	}

	le="$(read_status_field "last_errno")"
	if [[ "$le" != "0" ]]; then
		result "$num" "$name" FAIL "last_errno=$le, expected 0"
		rm -f "$testfile"
		return
	fi

	rm -f "$testfile"
	result "$num" "$name" PASS "file intact ($line_count lines)"
}

# --- Test 3: flock_after_reset ----------------------------------------------
#
# Take an exclusive flock, trigger reset, verify stale lock state is
# marked with CEPH_I_ERROR_FILELOCK (same-client flock attempt returns
# EIO).  After the original holder exits (releasing the local lock
# reference and clearing the error flag), a fresh lock can be acquired.
#
# The lock holder uses the fd-based flock form with exec, so killing
# $lock_pid closes the lock fd immediately (no orphaned child with an
# inherited fd copy that would prevent the VFS flock release).

test_flock_after_reset()
{
	local num=3
	local name="flock_after_reset"
	local testfile="$MOUNT_POINT/.reset_corner_flock_$$"
	local lock_pid probe_rc sc_before sc_after

	sc_before="$(read_status_field "success_count")"

	echo "flock_test_content" > "$testfile"
	sync "$testfile"

	# Hold lock via fd in a subshell; exec ensures killing $lock_pid
	# closes the lock fd directly (no fork/child fd inheritance).
	(
		exec 9<"$testfile"
		flock --exclusive --nonblock 9 || exit 1
		exec sleep 300
	) &
	lock_pid=$!
	sleep 0.5

	if ! kill -0 "$lock_pid" 2>/dev/null; then
		result "$num" "$name" FAIL "flock holder died immediately"
		rm -f "$testfile"
		return
	fi

	echo "flock_after_reset_test" > "$TRIGGER_PATH" 2>/dev/null || {
		kill "$lock_pid" 2>/dev/null; wait "$lock_pid" 2>/dev/null
		result "$num" "$name" FAIL "reset trigger failed"
		rm -f "$testfile"
		return
	}

	if ! wait_reset_done 30; then
		kill "$lock_pid" 2>/dev/null; wait "$lock_pid" 2>/dev/null
		result "$num" "$name" FAIL "reset did not complete"
		rm -f "$testfile"
		return
	fi

	sc_after="$(read_status_field "success_count")"
	if [[ "$sc_after" -le "$sc_before" ]]; then
		kill "$lock_pid" 2>/dev/null; wait "$lock_pid" 2>/dev/null
		result "$num" "$name" FAIL "success_count did not increment"
		rm -f "$testfile"
		return
	fi

	# After teardown, CEPH_I_ERROR_FILELOCK is set on the inode.
	# A same-client lock attempt should fail (EIO), NOT succeed.
	probe_rc=0
	flock --exclusive --nonblock "$testfile" true 2>/dev/null && probe_rc=0 || probe_rc=$?
	if [[ "$probe_rc" -eq 0 ]]; then
		kill "$lock_pid" 2>/dev/null; wait "$lock_pid" 2>/dev/null
		result "$num" "$name" FAIL \
			"same-client probe succeeded, expected EIO from stale lock state"
		rm -f "$testfile"
		return
	fi

	# Kill the holder -- the exec'd sleep IS $lock_pid, so killing it
	# closes fd 9 directly.  VFS flock release fires ceph_fl_release_lock(),
	# which decrements i_filelock_ref to 0 and clears CEPH_I_ERROR_FILELOCK.
	kill "$lock_pid" 2>/dev/null
	wait "$lock_pid" 2>/dev/null

	# After the holder exits, a fresh lock should be acquirable.
	# The reset teardown sends SESSION_REQUEST_CLOSE so the MDS
	# releases locks promptly, but retry briefly in case the
	# message races with the connection close.
	local attempt
	probe_rc=1
	for attempt in 1 2 3 4 5; do
		probe_rc=0
		flock --exclusive --nonblock "$testfile" true 2>/dev/null \
			&& probe_rc=0 || probe_rc=$?
		[[ "$probe_rc" -eq 0 ]] && break
		sleep 1
	done
	if [[ "$probe_rc" -ne 0 ]]; then
		result "$num" "$name" FAIL \
			"cannot acquire fresh lock after holder exit (rc=$probe_rc, ${attempt} attempts)"
		rm -f "$testfile"
		return
	fi

	# Verify file content survived
	grep -q "flock_test_content" "$testfile" 2>/dev/null || {
		result "$num" "$name" FAIL "file content corrupted after reset"
		rm -f "$testfile"
		return
	}

	rm -f "$testfile"
	result "$num" "$name" PASS "stale lock detected, fresh lock acquired after holder exit"
}

# --- Test 4: unmount_during_reset -------------------------------------------
#
# Mount a fresh CephFS, trigger reset, immediately unmount. The
# ceph_mdsc_destroy() path must wake blocked waiters with -ESHUTDOWN
# and not hang.

test_unmount_during_reset()
{
	local num=4
	local name="unmount_during_reset"
	local temp_mnt="/tmp/ceph_corner_mnt_$$"
	local mount_opts=""
	local mount_src=""
	local temp_trigger=""
	local temp_status=""
	local temp_client=""
	local temp_file="$temp_mnt/.reset_corner_umount_$$"
	local phase=""
	local trigger_ok=0
	local attempt
	local -a new_clients=()
	declare -A existing_clients=()

	mount_src="$(awk -v mp="$MOUNT_POINT" '$2 == mp && $3 == "ceph" {print $1; exit}' /proc/mounts 2>/dev/null)"
	mount_opts="$(awk -v mp="$MOUNT_POINT" '$2 == mp && $3 == "ceph" {print $4; exit}' /proc/mounts 2>/dev/null)"

	if [[ -z "$mount_src" ]]; then
		result "$num" "$name" SKIP "cannot determine mount source from /proc/mounts"
		return
	fi

	while IFS= read -r existing; do
		[[ -n "$existing" ]] || continue
		existing_clients["$existing"]=1
	done < <(list_reset_clients)

	mkdir -p "$temp_mnt"

	if ! mount -t ceph "$mount_src" "$temp_mnt" -o "$mount_opts" 2>/dev/null; then
		result "$num" "$name" SKIP "cannot mount additional CephFS instance"
		rmdir "$temp_mnt" 2>/dev/null
		return
	fi

	ls "$temp_mnt" > /dev/null 2>&1
	sync
	sleep 1

	for attempt in $(seq 1 50); do
		new_clients=()
		while IFS= read -r entry; do
			[[ -n "$entry" ]] || continue
			if [[ -n "${existing_clients[$entry]+x}" ]]; then
				continue
			fi
			new_clients+=("$entry")
		done < <(list_reset_clients)

		if [[ "${#new_clients[@]}" -eq 1 ]]; then
			temp_client="${new_clients[0]}"
			break
		fi

		if [[ "${#new_clients[@]}" -gt 1 ]]; then
			break
		fi

		sleep 0.1
	done

	if [[ -z "$temp_client" ]]; then
		umount "$temp_mnt" 2>/dev/null || umount -l "$temp_mnt" 2>/dev/null
		rmdir "$temp_mnt" 2>/dev/null
		result "$num" "$name" SKIP "cannot identify debugfs client for temp mount"
		return
	fi

	if [[ "${#new_clients[@]}" -gt 1 ]]; then
		umount "$temp_mnt" 2>/dev/null || umount -l "$temp_mnt" 2>/dev/null
		rmdir "$temp_mnt" 2>/dev/null
		result "$num" "$name" SKIP "multiple new debugfs clients appeared"
		return
	fi

	temp_trigger="$DEBUGFS_ROOT/$temp_client/reset/trigger"
	temp_status="$DEBUGFS_ROOT/$temp_client/reset/status"

	echo "umount_dirty_seed" > "$temp_file" 2>/dev/null || {
		umount "$temp_mnt" 2>/dev/null || umount -l "$temp_mnt" 2>/dev/null
		rmdir "$temp_mnt" 2>/dev/null
		result "$num" "$name" FAIL "cannot create dirty state on temp mount"
		return
	}
	sync "$temp_file"
	python3 -c "
import os, sys
fd = os.open('$temp_file', os.O_WRONLY | os.O_APPEND)
os.write(fd, b'dirty_for_umount_test\\n')
os.close(fd)
" 2>/dev/null || {
		umount "$temp_mnt" 2>/dev/null || umount -l "$temp_mnt" 2>/dev/null
		rmdir "$temp_mnt" 2>/dev/null
		result "$num" "$name" FAIL "cannot dirty temp mount for reset overlap"
		return
	}

	echo "unmount_test" > "$temp_trigger" 2>/dev/null && trigger_ok=1 || trigger_ok=0
	if [[ "$trigger_ok" -ne 1 ]]; then
		umount "$temp_mnt" 2>/dev/null || umount -l "$temp_mnt" 2>/dev/null
		rmdir "$temp_mnt" 2>/dev/null
		result "$num" "$name" FAIL "cannot trigger reset on temp mount"
		return
	fi

	if ! wait_status_nonidle "$temp_status" 10; then
		phase="$(awk -F': ' '$1 == "phase" {print $2}' "$temp_status" 2>/dev/null)"
		umount "$temp_mnt" 2>/dev/null || umount -l "$temp_mnt" 2>/dev/null
		rmdir "$temp_mnt" 2>/dev/null
		result "$num" "$name" FAIL \
			"reset never became active before umount (phase=${phase:-unknown})"
		return
	fi

	local umount_ok=0
	timeout 30 umount "$temp_mnt" 2>/dev/null && umount_ok=1

	if [[ "$umount_ok" -ne 1 ]]; then
		umount -l "$temp_mnt" 2>/dev/null || true
		rmdir "$temp_mnt" 2>/dev/null
		result "$num" "$name" FAIL "umount hung for >30s"
		return
	fi

	rmdir "$temp_mnt" 2>/dev/null

	ls "$MOUNT_POINT" > /dev/null 2>&1 || {
		result "$num" "$name" FAIL "original mount unhealthy after test"
		return
	}

	result "$num" "$name" PASS
}

# --- Main --------------------------------------------------------------------

usage()
{
	cat <<EOF
Usage: $0 --mount-point <path> [--client-id <id>] [--debugfs-root <path>]

Runs targeted corner-case tests for the CephFS client reset feature.
Requires root (debugfs access) and a mounted CephFS filesystem.

Options:
  --mount-point PATH     CephFS mount point (required)
  --client-id ID         Ceph debugfs client id (auto-detect if one client)
  --debugfs-root PATH    Debugfs ceph root (default: /sys/kernel/debug/ceph)
  --help                 Show this message
EOF
}

main()
{
	while [[ $# -gt 0 ]]; do
		case "$1" in
		--mount-point)   MOUNT_POINT="$2"; shift 2 ;;
		--client-id)     DEBUGFS_CLIENT="$2"; shift 2 ;;
		--debugfs-root)  DEBUGFS_ROOT="$2"; shift 2 ;;
		--help|-h)       usage; exit 0 ;;
		*)               echo "Unknown option: $1" >&2; usage; exit 2 ;;
		esac
	done

	if [[ -z "$MOUNT_POINT" ]]; then
		echo "--mount-point is required" >&2
		usage
		exit 2
	fi

	if [[ ! -d "$MOUNT_POINT" ]]; then
		echo "SKIP: Mount point does not exist: $MOUNT_POINT" >&2
		exit "$KSFT_SKIP"
	fi

	discover_debugfs
	TRIGGER_PATH="$DEBUGFS_ROOT/$DEBUGFS_CLIENT/reset/trigger"
	STATUS_PATH="$DEBUGFS_ROOT/$DEBUGFS_CLIENT/reset/status"

	log "CephFS client reset corner case tests"
	log "Mount: $MOUNT_POINT"
	log "Client: $DEBUGFS_CLIENT"
	echo ""

	test_ebusy_rejection
	test_dirty_caps_at_reset
	test_flock_after_reset
	test_unmount_during_reset

	echo ""
	echo "Results: $PASS_COUNT passed, $FAIL_COUNT failed, $SKIP_COUNT skipped (of $TOTAL)"

	if [[ "$FAIL_COUNT" -gt 0 ]]; then
		exit 1
	fi
	exit 0
}

main "$@"
