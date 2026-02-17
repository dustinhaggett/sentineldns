from __future__ import annotations

import csv
import fnmatch
import hashlib
import json
import time
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from sentineldns.features.window_features import aggregate_events_to_windows
from sentineldns.models.anomaly import load_anomaly_bundle, score_window
from sentineldns.models.domain_risk import load_domain_risk_bundle, score_domain
from sentineldns.models.explain import explain_anomaly_result


@dataclass
class LivePrivacyConfig:
    hash_domains: bool = False
    hash_salt: str = "sentineldns-local"
    exclude_patterns: list[str] | None = None
    retention_days: int = 14


def should_exclude_domain(domain: str, exclude_patterns: list[str] | None) -> bool:
    if not exclude_patterns:
        return False
    return any(fnmatch.fnmatch(domain, pattern) for pattern in exclude_patterns)


def redact_domain(domain: str, hash_domains: bool, hash_salt: str) -> str:
    if not hash_domains:
        return domain
    digest = hashlib.sha256(f"{hash_salt}:{domain}".encode("utf-8")).hexdigest()
    return f"sha256:{digest[:20]}"


def _read_new_jsonl(path: Path, offset_bytes: int) -> tuple[list[dict[str, Any]], int]:
    if not path.exists():
        return [], offset_bytes
    events: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8", errors="ignore") as fh:
        fh.seek(offset_bytes)
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                parsed = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(parsed, dict):
                events.append(parsed)
        new_offset = fh.tell()
    return events, new_offset


def _append_csv_row(path: Path, row: dict[str, Any], fieldnames: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    file_exists = path.exists()
    with path.open("a", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        if not file_exists:
            writer.writeheader()
        writer.writerow(row)


def purge_old_rows_csv(path: Path, timestamp_col: str, retention_days: int) -> None:
    if not path.exists() or retention_days <= 0:
        return
    cutoff = datetime.now().astimezone() - timedelta(days=retention_days)
    with path.open("r", encoding="utf-8", newline="") as fh:
        reader = csv.DictReader(fh)
        fieldnames = reader.fieldnames or []
        rows = list(reader)
    kept: list[dict[str, Any]] = []
    for row in rows:
        value = row.get(timestamp_col, "")
        try:
            ts = datetime.fromisoformat(value)
        except ValueError:
            kept.append(row)
            continue
        if ts >= cutoff:
            kept.append(row)
    with path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        if fieldnames:
            writer.writeheader()
            writer.writerows(kept)


def run_live_monitor(
    input_file: Path,
    output_csv: Path,
    alerts_csv: Path,
    privacy: LivePrivacyConfig,
    poll_seconds: float = 2.0,
    window_minutes: int = 5,
    once: bool = False,
    start_at_end: bool = False,
) -> None:
    domain_bundle = load_domain_risk_bundle()
    anomaly_bundle = load_anomaly_bundle()
    offset_bytes = input_file.stat().st_size if (start_at_end and input_file.exists()) else 0

    scored_events: list[dict[str, Any]] = []
    emitted_windows: set[str] = set()

    while True:
        new_events, offset_bytes = _read_new_jsonl(input_file, offset_bytes)
        if new_events:
            for event in new_events:
                domain = str(event.get("domain", "")).strip().lower()
                ts = str(event.get("ts", ""))
                if not domain or not ts:
                    continue
                if should_exclude_domain(domain, privacy.exclude_patterns):
                    continue
                scored = score_domain(domain, domain_bundle)
                display_domain = redact_domain(
                    domain=domain,
                    hash_domains=privacy.hash_domains,
                    hash_salt=privacy.hash_salt,
                )
                row = {
                    "ts": ts,
                    "domain": display_domain,
                    "rcode": str(event.get("rcode", "NOERROR")),
                    "qtype": str(event.get("qtype", "A")),
                    "risk_score": scored["risk_score"],
                    "risk_label": scored["risk_label"],
                    "reason_tags": "|".join(scored["reason_tags"]),
                }
                _append_csv_row(
                    path=output_csv,
                    row=row,
                    fieldnames=[
                        "ts",
                        "domain",
                        "rcode",
                        "qtype",
                        "risk_score",
                        "risk_label",
                        "reason_tags",
                    ],
                )
                scored_events.append(
                    {
                        "ts": ts,
                        "domain": domain,
                        "rcode": str(event.get("rcode", "NOERROR")),
                        "score": float(scored["risk_score"]),
                    }
                )
                print(f"[live] {ts} {display_domain:<32} {scored['risk_label']:<18} {scored['risk_score']:.1f}")

            domain_scores = {item["domain"]: item["score"] for item in scored_events}
            event_rows = [{"ts": e["ts"], "domain": e["domain"], "rcode": e["rcode"], "qtype": "A"} for e in scored_events]
            windows = aggregate_events_to_windows(
                event_rows,
                domain_scores=domain_scores,
                window_minutes=window_minutes,
            )
            for window in windows:
                if window.window_end in emitted_windows:
                    continue
                result = score_window(window, anomaly_bundle)
                explained = explain_anomaly_result(
                    anomaly_score=result["anomaly_score"],
                    reason_tags=result["reason_tags"],
                    queries_per_min=window.queries_per_min,
                    nxdomain_rate=window.nxdomain_rate,
                )
                alert_row = {
                    "window_start": window.window_start,
                    "window_end": window.window_end,
                    "anomaly_score": result["anomaly_score"],
                    "anomaly_label": result["anomaly_label"],
                    "reason_tags": "|".join(result["reason_tags"]),
                    "summary": explained["summary"],
                    "recommended_action": explained["recommended_action"],
                }
                _append_csv_row(
                    path=alerts_csv,
                    row=alert_row,
                    fieldnames=[
                        "window_start",
                        "window_end",
                        "anomaly_score",
                        "anomaly_label",
                        "reason_tags",
                        "summary",
                        "recommended_action",
                    ],
                )
                emitted_windows.add(window.window_end)
                if result["anomaly_label"] != "Normal":
                    print(
                        f"[live-alert] {window.window_start} -> {result['anomaly_label']} "
                        f"(score={result['anomaly_score']:.2f})"
                    )

            purge_old_rows_csv(output_csv, timestamp_col="ts", retention_days=privacy.retention_days)
            purge_old_rows_csv(alerts_csv, timestamp_col="window_end", retention_days=privacy.retention_days)

        if once:
            break
        time.sleep(max(poll_seconds, 0.1))
