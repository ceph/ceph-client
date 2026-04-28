#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# CephFS reset stress test:
# - Runs concurrent I/O and rename workloads
# - Triggers random client resets through debugfs
# - Validates consistency and recovery behavior

set -euo pipefail

KSFT_SKIP=4
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

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

PROFILE="moderate"
DURATION_SEC=""
COOLDOWN_SEC=20
FILE_COUNT=64
IO_WORKERS=""
RENAME_WORKERS=""
MOUNT_POINT=""
OUT_DIR=""
CLIENT_ID=""
DEBUGFS_ROOT="/sys/kernel/debug/ceph"
SLO_SECONDS=30
EXPECT_RESET=1
DMESG_CMD=""
SUDO=""

RESET_MIN_SEC=5
RESET_MAX_SEC=15

RUN_ID="$(date +%Y%m%d-%H%M%S)"
WORKLOAD_FLAG=""
RESET_FLAG=""
DATA_DIR=""

IO_LOG=""
RENAME_LOG=""
RESET_LOG=""
STATUS_LOG=""
STATUS_BEFORE=""
STATUS_FINAL=""
DMESG_LOG=""
SUMMARY_LOG=""
REPORT_JSON=""

RESET_PID=0
STATUS_PID=0
declare -a IO_WORKER_PIDS=()
declare -a RENAME_WORKER_PIDS=()

usage()
{
	cat <<EOF
Usage: $0 --mount-point <cephfs_mount> [options]

Required:
  --mount-point PATH       CephFS mount point to test under

Options:
  --profile NAME           baseline|moderate|aggressive|soak (default: moderate)
  --duration-sec N         Override profile runtime in seconds
  --cooldown-sec N         Workload drain time after injector stop (default: 20)
  --file-count N           Number of logical files (default: 64)
  --io-workers N           Number of concurrent I/O workers (profile default)
  --rename-workers N       Number of concurrent rename workers (profile default)
  --out-dir PATH           Artifact directory (default: /tmp/ceph_reset_stress_<ts>)
  --client-id ID           Ceph debugfs client id; auto-detect if one client exists
  --debugfs-root PATH      Debugfs Ceph root (default: /sys/kernel/debug/ceph)
  --slo-seconds N          Max allowed post-reset stall window (default: 30)
  --no-reset               Disable reset injector (baseline mode helper)
  --help                   Show this message

Examples:
  $0 --mount-point /mnt/cephfs --profile moderate
  $0 --mount-point /mnt/cephfs --profile aggressive --duration-sec 300
  $0 --mount-point /mnt/cephfs --profile baseline --no-reset
EOF
}

now_ms()
{
	date +%s%3N
}

set_profile_defaults()
{
	case "$PROFILE" in
	baseline)
		RESET_MIN_SEC=0
		RESET_MAX_SEC=0
		EXPECT_RESET=0
		: "${DURATION_SEC:=600}"
		: "${IO_WORKERS:=1}"
		: "${RENAME_WORKERS:=1}"
		;;
	moderate)
		RESET_MIN_SEC=5
		RESET_MAX_SEC=15
		: "${DURATION_SEC:=900}"
		: "${IO_WORKERS:=2}"
		: "${RENAME_WORKERS:=1}"
		;;
	aggressive)
		RESET_MIN_SEC=1
		RESET_MAX_SEC=5
		: "${DURATION_SEC:=900}"
		: "${IO_WORKERS:=4}"
		: "${RENAME_WORKERS:=2}"
		;;
	soak)
		RESET_MIN_SEC=5
		RESET_MAX_SEC=15
		: "${DURATION_SEC:=3600}"
		: "${IO_WORKERS:=2}"
		: "${RENAME_WORKERS:=1}"
		;;
	*)
		echo "Unknown profile: $PROFILE" >&2
		exit 2
		;;
	esac
}

log_summary()
{
	local msg="$1"
	printf '[%s] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$msg" | tee -a "$SUMMARY_LOG"
}

discover_client_id()
{
	local candidates=()
	local entry

	if [[ -n "$CLIENT_ID" ]]; then
		if ! $SUDO test -d "$DEBUGFS_ROOT/$CLIENT_ID/reset"; then
			echo "SKIP: reset debugfs not found for client-id=$CLIENT_ID" >&2
			exit "$KSFT_SKIP"
		fi
		return 0
	fi

	if ! $SUDO test -d "$DEBUGFS_ROOT"; then
		echo "SKIP: Debugfs root not found: $DEBUGFS_ROOT" >&2
		exit "$KSFT_SKIP"
	fi

	while IFS= read -r entry; do
		$SUDO test -d "$DEBUGFS_ROOT/$entry/reset" || continue
		$SUDO test -w "$DEBUGFS_ROOT/$entry/reset/trigger" || continue
		candidates+=("$entry")
	done < <($SUDO ls -1 "$DEBUGFS_ROOT" 2>/dev/null || true)

	if [[ ${#candidates[@]} -eq 1 ]]; then
		CLIENT_ID="${candidates[0]}"
		return 0
	fi

	if [[ ${#candidates[@]} -eq 0 ]]; then
		echo "SKIP: No writable Ceph reset interface found under $DEBUGFS_ROOT" >&2
		exit "$KSFT_SKIP"
	fi

	echo "SKIP: Multiple Ceph clients found (${candidates[*]}). Use --client-id." >&2
	exit "$KSFT_SKIP"
}

init_dataset()
{
	local i
	mkdir -p "$DATA_DIR/A" "$DATA_DIR/B"

	for ((i = 0; i < FILE_COUNT; i++)); do
		printf 'seed logical_id=%05d ts_ms=%s\n' "$i" "$(now_ms)" > "$DATA_DIR/A/file_$(printf '%05d' "$i")"
	done
}

io_worker()
{
	set +e
	local worker_id="$1"
	local seq=0
	local id
	local relpath
	local abspath
	local payload
	local hash
	local ts

	while [[ -f "$WORKLOAD_FLAG" ]]; do
		id="$(printf '%05d' $((RANDOM % FILE_COUNT)))"
		if [[ -f "$DATA_DIR/A/file_$id" ]]; then
			relpath="A/file_$id"
		elif [[ -f "$DATA_DIR/B/file_$id" ]]; then
			relpath="B/file_$id"
		else
			sleep 0.02
			continue
		fi

		abspath="$DATA_DIR/$relpath"
		alt_relpath=""
		if [[ "$relpath" == A/* ]]; then
			alt_relpath="B/file_$id"
		else
			alt_relpath="A/file_$id"
		fi
		alt_abspath="$DATA_DIR/$alt_relpath"
		payload="worker=${worker_id} io_seq=${seq} id=${id} ts_ms=$(now_ms)"
		result="$(
			python3 - "$abspath" "$alt_abspath" "$payload" <<'PY'
import hashlib
import os
import sys

path = sys.argv[1]
alt_path = sys.argv[2]
payload = sys.argv[3]

try:
    fd = os.open(path, os.O_RDWR | os.O_APPEND)
    actual = path
except FileNotFoundError:
    try:
        fd = os.open(alt_path, os.O_RDWR | os.O_APPEND)
        actual = alt_path
    except FileNotFoundError:
        sys.exit(1)

try:
    os.write(fd, (payload + "\n").encode())
    os.fsync(fd)
    os.lseek(fd, 0, os.SEEK_SET)
    digest = hashlib.sha256()
    while True:
        chunk = os.read(fd, 1 << 20)
        if not chunk:
            break
        digest.update(chunk)
    print(actual + " " + digest.hexdigest())
finally:
    os.close(fd)
PY
		)" || {
			sleep 0.02
			continue
		}

		actual_abspath="${result%% *}"
		hash="${result#* }"
		if [[ "$actual_abspath" == "$alt_abspath" ]]; then
			relpath="$alt_relpath"
		fi

		ts="$(now_ms)"
		printf '%s,%s,%s,%s,%s\n' "$ts" "$seq" "$id" "$relpath" "$hash" >> "$IO_LOG"
		seq=$((seq + 1))
		sleep 0.02
	done
}

rename_worker()
{
	set +e
	local worker_id="$1"
	local seq=0
	local id
	local src_rel
	local dst_rel
	local rc
	local ts

	while [[ -f "$WORKLOAD_FLAG" ]]; do
		id="$(printf '%05d' $((RANDOM % FILE_COUNT)))"

		if [[ -f "$DATA_DIR/A/file_$id" ]]; then
			src_rel="A/file_$id"
			dst_rel="B/file_$id"
		elif [[ -f "$DATA_DIR/B/file_$id" ]]; then
			src_rel="B/file_$id"
			dst_rel="A/file_$id"
		else
			sleep 0.02
			continue
		fi

		ts="$(now_ms)"
		if mv -T "$DATA_DIR/$src_rel" "$DATA_DIR/$dst_rel" 2>/dev/null; then
			rc=0
		else
			rc=$?
		fi
		printf '%s,%s,%s,%s,%s,%s,%s\n' "$ts" "$worker_id" "$seq" "$id" "$src_rel" "$dst_rel" "$rc" >> "$RENAME_LOG"
		seq=$((seq + 1))
		sleep 0.02
	done
}

random_sleep_seconds()
{
	local min_sec="$1"
	local max_sec="$2"
	local wait_sec
	local span

	span=$((max_sec - min_sec + 1))
	wait_sec=$((min_sec + RANDOM % span))
	sleep "$wait_sec"
}

reset_injector()
{
	set +e
	local trigger_path="$1"
	local seq=0
	local ts
	local reason
	local rc

	while [[ -f "$RESET_FLAG" ]]; do
		random_sleep_seconds "$RESET_MIN_SEC" "$RESET_MAX_SEC"
		[[ -f "$RESET_FLAG" ]] || break

		ts="$(now_ms)"
		reason="stress_${seq}_${ts}"
		if echo "$reason" | $SUDO tee "$trigger_path" > /dev/null 2>&1; then
			rc=0
		else
			rc=$?
		fi
		printf '%s,%s,%s,%s\n' "$ts" "$seq" "$reason" "$rc" >> "$RESET_LOG"
		seq=$((seq + 1))
	done
}

status_sampler()
{
	set +e
	local status_path="$1"
	local ts
	local kv_line

	while [[ -f "$WORKLOAD_FLAG" || -f "$RESET_FLAG" ]]; do
		ts="$(now_ms)"
		if $SUDO test -r "$status_path"; then
			kv_line="$($SUDO awk -F': ' 'NF>=2 {gsub(/ /, "", $1); gsub(/ /, "", $2); printf "%s=%s;", $1, $2}' "$status_path")"
			printf '%s,%s\n' "$ts" "$kv_line" >> "$STATUS_LOG"
		fi
		sleep 1
	done
}

stop_pid_with_timeout()
{
	local pid="$1"
	local name="$2"
	local timeout="$3"
	local waited=0

	if [[ "$pid" -le 0 ]]; then
		return 0
	fi

	while kill -0 "$pid" 2>/dev/null; do
		if (( waited >= timeout )); then
			log_summary "Timeout waiting for $name (pid=$pid), sending SIGTERM/SIGKILL"
			kill -TERM "$pid" 2>/dev/null || true
			sleep 1
			kill -KILL "$pid" 2>/dev/null || true
			wait "$pid" 2>/dev/null || true
			return 1
		fi
		sleep 1
		waited=$((waited + 1))
	done

	wait "$pid" 2>/dev/null || true
	return 0
}

detect_privileges()
{
	if [[ -r "$DEBUGFS_ROOT" ]]; then
		SUDO=""
	elif sudo -n true 2>/dev/null; then
		SUDO="sudo"
	else
		echo "WARNING: $DEBUGFS_ROOT is not readable and passwordless sudo is not available" >&2
		echo "WARNING: reset injection, debugfs status checks, and dmesg capture will not work" >&2
	fi

	if $SUDO dmesg > /dev/null 2>&1; then
		DMESG_CMD="$SUDO dmesg"
	else
		DMESG_CMD=""
		echo "WARNING: dmesg is not accessible; kernel errors (hung tasks) will not be detected" >&2
	fi
}

check_dmesg()
{
	local start_epoch="$1"

	if [[ -z "$DMESG_CMD" ]]; then
		return 0
	fi

	if ! $DMESG_CMD --since "@$start_epoch" > "$DMESG_LOG" 2>/dev/null; then
		if ! $DMESG_CMD > "$DMESG_LOG" 2>/dev/null; then
			log_summary "WARNING: dmesg capture failed unexpectedly"
			return 0
		fi
		log_summary "dmesg --since unsupported; captured full dmesg"
	fi

	if grep -qi "hung task" "$DMESG_LOG" 2>/dev/null; then
		log_summary "ERROR: kernel log contains 'hung task' during test window"
		return 1
	fi

	return 0
}

cleanup()
{
	rm -f "$WORKLOAD_FLAG" "$RESET_FLAG"
	local pid
	for pid in "${IO_WORKER_PIDS[@]}" "${RENAME_WORKER_PIDS[@]}" "$RESET_PID" "$STATUS_PID"; do
		[[ "$pid" -gt 0 ]] 2>/dev/null && kill "$pid" 2>/dev/null || true
	done
	wait 2>/dev/null || true
}

parse_args()
{
	while [[ $# -gt 0 ]]; do
		case "$1" in
		--mount-point)
			MOUNT_POINT="$2"
			shift 2
			;;
		--profile)
			PROFILE="$2"
			shift 2
			;;
		--duration-sec)
			DURATION_SEC="$2"
			shift 2
			;;
		--cooldown-sec)
			COOLDOWN_SEC="$2"
			shift 2
			;;
		--file-count)
			FILE_COUNT="$2"
			shift 2
			;;
		--io-workers)
			IO_WORKERS="$2"
			shift 2
			;;
		--rename-workers)
			RENAME_WORKERS="$2"
			shift 2
			;;
		--out-dir)
			OUT_DIR="$2"
			shift 2
			;;
		--client-id)
			CLIENT_ID="$2"
			shift 2
			;;
		--debugfs-root)
			DEBUGFS_ROOT="$2"
			shift 2
			;;
		--slo-seconds)
			SLO_SECONDS="$2"
			shift 2
			;;
		--no-reset)
			EXPECT_RESET=0
			shift
			;;
		--help|-h)
			usage
			exit 0
			;;
		*)
			echo "Unknown option: $1" >&2
			usage
			exit 2
			;;
		esac
	done
}

main()
{
	local start_epoch
	local trigger_path=""
	local status_path=""
	local final_rc=0
	local reset_enabled=0
	local i

	parse_args "$@"

	if [[ -z "$MOUNT_POINT" ]]; then
		echo "--mount-point is required" >&2
		usage
		exit 2
	fi

	if [[ ! -d "$MOUNT_POINT" ]]; then
		echo "SKIP: Mount point does not exist: $MOUNT_POINT" >&2
		exit "$KSFT_SKIP"
	fi

	if ! touch "$MOUNT_POINT/.ceph_reset_test_probe" 2>/dev/null; then
		echo "SKIP: Mount point is not writable: $MOUNT_POINT" >&2
		exit "$KSFT_SKIP"
	fi
	rm -f "$MOUNT_POINT/.ceph_reset_test_probe"

	if ! command -v python3 > /dev/null 2>&1; then
		echo "SKIP: python3 is required but not found in PATH" >&2
		exit "$KSFT_SKIP"
	fi

	if ! stat -f -c '%T' "$MOUNT_POINT" 2>/dev/null | grep -qi ceph; then
		echo "WARNING: $MOUNT_POINT does not appear to be a CephFS mount" >&2
	fi

	detect_privileges

	set_profile_defaults
	if [[ "$EXPECT_RESET" -eq 0 ]]; then
		PROFILE="baseline"
		RESET_MIN_SEC=0
		RESET_MAX_SEC=0
	fi

	if ! [[ "$IO_WORKERS" =~ ^[0-9]+$ && "$RENAME_WORKERS" =~ ^[0-9]+$ ]]; then
		echo "io-workers and rename-workers must be integers" >&2
		exit 2
	fi

	if [[ "$IO_WORKERS" -le 0 || "$RENAME_WORKERS" -le 0 ]]; then
		echo "io-workers and rename-workers must be > 0" >&2
		exit 2
	fi

	if [[ -z "$OUT_DIR" ]]; then
		OUT_DIR="/tmp/ceph_reset_stress_${RUN_ID}"
	fi
	mkdir -p "$OUT_DIR"

	WORKLOAD_FLAG="$OUT_DIR/workload.running"
	RESET_FLAG="$OUT_DIR/reset.running"

	DATA_DIR="$MOUNT_POINT/ceph_reset_stress_${RUN_ID}"
	mkdir -p "$DATA_DIR"

	IO_LOG="$OUT_DIR/io.log"
	RENAME_LOG="$OUT_DIR/rename.log"
	RESET_LOG="$OUT_DIR/reset.log"
	STATUS_LOG="$OUT_DIR/status.log"
	STATUS_BEFORE="$OUT_DIR/reset_status.before"
	STATUS_FINAL="$OUT_DIR/reset_status.final"
	DMESG_LOG="$OUT_DIR/dmesg.log"
	SUMMARY_LOG="$OUT_DIR/summary.log"
	REPORT_JSON="$OUT_DIR/validator_report.json"

	: > "$IO_LOG"
	: > "$RENAME_LOG"
	: > "$RESET_LOG"
	: > "$STATUS_LOG"
	: > "$SUMMARY_LOG"

	start_epoch="$(date +%s)"

	log_summary "Starting Ceph reset stress test"
	log_summary "Profile=$PROFILE duration=${DURATION_SEC}s cooldown=${COOLDOWN_SEC}s file_count=${FILE_COUNT} io_workers=${IO_WORKERS} rename_workers=${RENAME_WORKERS}"
	[[ -n "$SUDO" ]] && log_summary "Using sudo for privileged operations"
	[[ -z "$DMESG_CMD" ]] && log_summary "WARNING: dmesg not available; hung task detection disabled"
	log_summary "Artifacts=$OUT_DIR"
	log_summary "Data dir=$DATA_DIR"

	init_dataset

	if [[ "$EXPECT_RESET" -eq 1 ]]; then
		discover_client_id
		trigger_path="$DEBUGFS_ROOT/$CLIENT_ID/reset/trigger"
		status_path="$DEBUGFS_ROOT/$CLIENT_ID/reset/status"
		if ! $SUDO test -w "$trigger_path"; then
			echo "SKIP: Reset trigger is not writable: $trigger_path" >&2
			exit "$KSFT_SKIP"
		fi
		if ! $SUDO test -r "$status_path"; then
			echo "SKIP: Reset status is not readable: $status_path" >&2
			exit "$KSFT_SKIP"
		fi
		$SUDO cat "$status_path" > "$STATUS_BEFORE" || true
		reset_enabled=1
		log_summary "Using ceph client id: $CLIENT_ID"
	fi

	trap cleanup EXIT INT TERM

	touch "$WORKLOAD_FLAG"
	for ((i = 0; i < IO_WORKERS; i++)); do
		io_worker "$i" &
		IO_WORKER_PIDS+=("$!")
	done

	for ((i = 0; i < RENAME_WORKERS; i++)); do
		rename_worker "$i" &
		RENAME_WORKER_PIDS+=("$!")
	done

	if [[ "$reset_enabled" -eq 1 ]]; then
		touch "$RESET_FLAG"
		reset_injector "$trigger_path" &
		RESET_PID=$!

		status_sampler "$status_path" &
		STATUS_PID=$!
	fi

	sleep "$DURATION_SEC"

	if [[ "$reset_enabled" -eq 1 ]]; then
		rm -f "$RESET_FLAG"
		stop_pid_with_timeout "$RESET_PID" "reset_injector" 20 || final_rc=1
		log_summary "Injector stopped; entering cooldown=${COOLDOWN_SEC}s"
	fi

	sleep "$COOLDOWN_SEC"

	rm -f "$WORKLOAD_FLAG"
	for i in "${!IO_WORKER_PIDS[@]}"; do
		stop_pid_with_timeout "${IO_WORKER_PIDS[$i]}" "io_worker[$i]" 20 || final_rc=1
	done
	for i in "${!RENAME_WORKER_PIDS[@]}"; do
		stop_pid_with_timeout "${RENAME_WORKER_PIDS[$i]}" "rename_worker[$i]" 20 || final_rc=1
	done

	if [[ "$reset_enabled" -eq 1 ]]; then
		stop_pid_with_timeout "$STATUS_PID" "status_sampler" 10 || final_rc=1
		$SUDO cat "$status_path" > "$STATUS_FINAL" || true
	fi

	if ! check_dmesg "$start_epoch"; then
		final_rc=1
	fi

	if ! python3 "$SCRIPT_DIR/validate_consistency.py" \
		--data-dir "$DATA_DIR" \
		--file-count "$FILE_COUNT" \
		--io-log "$IO_LOG" \
		--rename-log "$RENAME_LOG" \
		--reset-log "$RESET_LOG" \
		--status-final "$STATUS_FINAL" \
		--slo-seconds "$SLO_SECONDS" \
		--report-json "$REPORT_JSON" \
		$( [[ "$reset_enabled" -eq 1 ]] && echo "--expect-reset" ); then
		final_rc=1
	fi

	if [[ "$final_rc" -eq 0 ]]; then
		log_summary "PASS: stress run completed successfully"
	else
		log_summary "FAIL: stress run detected one or more failures"
	fi

	log_summary "Artifacts available in: $OUT_DIR"
	exit "$final_rc"
}

main "$@"
