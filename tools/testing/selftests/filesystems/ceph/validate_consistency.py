#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0

import argparse
import bisect
import hashlib
import json
import os
from pathlib import Path


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(1 << 20)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def parse_io_log(path: Path):
    records = []
    if not path.exists():
        return records
    with path.open("r", encoding="utf-8") as handle:
        for line_no, line in enumerate(handle, 1):
            line = line.strip()
            if not line:
                continue
            parts = line.split(",")
            if len(parts) != 5:
                raise ValueError(f"io log line {line_no}: expected 5 columns, got {len(parts)}")
            ts_ms, seq, logical_id, relpath, digest = parts
            records.append(
                {
                    "ts_ms": int(ts_ms),
                    "seq": int(seq),
                    "logical_id": int(logical_id),
                    "relpath": relpath,
                    "digest": digest,
                }
            )
    return records


def parse_rename_log(path: Path):
    records = []
    if not path.exists():
        return records
    with path.open("r", encoding="utf-8") as handle:
        for line_no, line in enumerate(handle, 1):
            line = line.strip()
            if not line:
                continue
            parts = line.split(",")
            if len(parts) == 6:
                ts_ms, seq, logical_id, src_rel, dst_rel, rc = parts
            elif len(parts) == 7:
                ts_ms, worker_id, seq, logical_id, src_rel, dst_rel, rc = parts
                _ = worker_id  # worker id is informational only
            else:
                raise ValueError(
                    f"rename log line {line_no}: expected 6 or 7 columns, got {len(parts)}"
                )
            records.append(
                {
                    "ts_ms": int(ts_ms),
                    "seq": int(seq),
                    "logical_id": int(logical_id),
                    "src_rel": src_rel,
                    "dst_rel": dst_rel,
                    "rc": int(rc),
                }
            )
    return records


def parse_reset_log(path: Path):
    records = []
    if not path.exists():
        return records
    with path.open("r", encoding="utf-8") as handle:
        for line_no, line in enumerate(handle, 1):
            line = line.strip()
            if not line:
                continue
            parts = line.split(",")
            if len(parts) != 4:
                raise ValueError(f"reset log line {line_no}: expected 4 columns, got {len(parts)}")
            ts_ms, seq, reason, rc = parts
            records.append(
                {
                    "ts_ms": int(ts_ms),
                    "seq": int(seq),
                    "reason": reason,
                    "rc": int(rc),
                }
            )
    return records


def parse_status_file(path: Path):
    status = {}
    if not path.exists():
        return status
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line or ":" not in line:
                continue
            key, value = line.split(":", 1)
            status[key.strip()] = value.strip()
    return status


def to_int(value: str, default: int = 0):
    try:
        return int(value)
    except Exception:
        return default


def validate_namespace(data_dir: Path, file_count: int, issues):
    actual_locations = {}
    actual_paths = {}
    for logical_id in range(file_count):
        name = f"file_{logical_id:05d}"
        found = []
        for subdir in ("A", "B"):
            candidate = data_dir / subdir / name
            if candidate.exists():
                found.append((subdir, candidate))
        if len(found) != 1:
            issues.append(
                f"namespace invariant failed for logical_id={logical_id:05d}: expected exactly one file in A/B, found {len(found)}"
            )
            continue
        actual_locations[logical_id] = found[0][0]
        actual_paths[logical_id] = found[0][1]
    return actual_locations, actual_paths


def validate_rename_invariant(rename_records, actual_locations, issues):
    expected_locations = {}
    for rec in rename_records:
        if rec["rc"] != 0:
            continue
        dst = rec["dst_rel"]
        if "/" not in dst:
            continue
        expected_locations[rec["logical_id"]] = dst.split("/", 1)[0]

    for logical_id, expected in expected_locations.items():
        actual = actual_locations.get(logical_id)
        if actual is None:
            continue
        if actual != expected:
            issues.append(
                f"rename invariant failed for logical_id={logical_id:05d}: expected location={expected}, actual={actual}"
            )


def validate_data_invariant(io_records, actual_paths, issues):
    expected_hash = {}
    for rec in io_records:
        digest = rec["digest"]
        if not digest:
            continue
        expected_hash[rec["logical_id"]] = digest

    for logical_id, digest in expected_hash.items():
        path = actual_paths.get(logical_id)
        if path is None:
            continue
        actual_digest = sha256_file(path)
        if digest != actual_digest:
            issues.append(
                f"data invariant failed for logical_id={logical_id:05d}: expected digest={digest}, actual digest={actual_digest}"
            )


def validate_reset_and_slo(args, reset_records, io_records, rename_records, status, issues):
    if not args.expect_reset:
        return

    successful_reset_times = [rec["ts_ms"] for rec in reset_records if rec["rc"] == 0]
    if not successful_reset_times:
        issues.append("expected reset activity but no successful reset trigger was observed")

    phase = status.get("phase")
    blocked_requests = to_int(status.get("blocked_requests", "0"), default=-1)
    last_errno = to_int(status.get("last_errno", "0"), default=1)
    failure_count = to_int(status.get("failure_count", "0"), default=-1)

    if phase is None:
        issues.append("missing final reset status file or phase field")
    elif phase.lower() != "idle":
        issues.append(f"recovery invariant failed: phase={phase}, expected idle")

    if blocked_requests != 0:
        issues.append(f"recovery invariant failed: blocked_requests={blocked_requests}, expected 0")
    if last_errno != 0:
        issues.append(f"recovery invariant failed: last_errno={last_errno}, expected 0")
    if failure_count > 0:
        issues.append(
            f"recovery invariant failed: failure_count={failure_count}, "
            "one or more resets failed during the run"
        )

    op_times = [rec["ts_ms"] for rec in io_records]
    op_times.extend(rec["ts_ms"] for rec in rename_records if rec["rc"] == 0)
    op_times.sort()

    if successful_reset_times and not op_times:
        issues.append("recovery SLO failed: no workload completion events were recorded")
        return

    slo_ms = args.slo_seconds * 1000
    for ts in successful_reset_times:
        idx = bisect.bisect_left(op_times, ts)
        if idx >= len(op_times):
            issues.append(f"recovery SLO failed: no operation completion observed after reset at ts_ms={ts}")
            continue
        delta = op_times[idx] - ts
        if delta > slo_ms:
            issues.append(
                f"recovery SLO failed: first post-reset completion at {delta}ms exceeds threshold {slo_ms}ms (reset ts_ms={ts})"
            )


def main():
    parser = argparse.ArgumentParser(description="Validate Ceph reset stress artifacts")
    parser.add_argument("--data-dir", required=True)
    parser.add_argument("--file-count", required=True, type=int)
    parser.add_argument("--io-log", required=True)
    parser.add_argument("--rename-log", required=True)
    parser.add_argument("--reset-log", required=True)
    parser.add_argument("--status-final", required=False, default="")
    parser.add_argument("--slo-seconds", required=False, type=int, default=30)
    parser.add_argument("--expect-reset", action="store_true")
    parser.add_argument("--report-json", required=False, default="")
    args = parser.parse_args()

    data_dir = Path(args.data_dir)
    io_log = Path(args.io_log)
    rename_log = Path(args.rename_log)
    reset_log = Path(args.reset_log)
    status_final = Path(args.status_final) if args.status_final else Path("__missing_status__")

    issues = []

    if not data_dir.exists():
        issues.append(f"data directory is missing: {data_dir}")

    try:
        io_records = parse_io_log(io_log)
        rename_records = parse_rename_log(rename_log)
        reset_records = parse_reset_log(reset_log)
    except Exception as exc:
        issues.append(f"log parsing failed: {exc}")
        io_records = []
        rename_records = []
        reset_records = []

    status = parse_status_file(status_final)

    actual_locations, actual_paths = validate_namespace(data_dir, args.file_count, issues)
    validate_rename_invariant(rename_records, actual_locations, issues)
    validate_data_invariant(io_records, actual_paths, issues)
    validate_reset_and_slo(args, reset_records, io_records, rename_records, status, issues)

    report = {
        "file_count": args.file_count,
        "io_records": len(io_records),
        "rename_records": len(rename_records),
        "reset_records": len(reset_records),
        "expect_reset": args.expect_reset,
        "issues": issues,
    }

    if args.report_json:
        report_path = Path(args.report_json)
        report_path.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")

    if issues:
        print("FAIL: consistency validation found issues")
        for issue in issues:
            print(f"  - {issue}")
        raise SystemExit(1)

    print("PASS: consistency validation succeeded")


if __name__ == "__main__":
    main()
