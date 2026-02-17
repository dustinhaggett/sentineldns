from __future__ import annotations

import argparse
import json
import sqlite3
import time
from datetime import datetime
from pathlib import Path
from urllib.request import Request, urlopen

import pandas as pd

from sentineldns.config import PROCESSED_DIR, RAW_DIR, SIMULATION_DIR
from sentineldns.data.build_dataset import build_labeled_dataset
from sentineldns.data.download import download_phishtank, download_tranco, download_urlhaus
from sentineldns.data.live_monitor import LivePrivacyConfig, run_live_monitor
from sentineldns.data.simulations import write_simulation_jsonl
from sentineldns.features.window_features import aggregate_events_to_windows
from sentineldns.logging_utils import configure_logging
from sentineldns.models.anomaly import train_anomaly_model
from sentineldns.models.domain_risk import train_domain_risk_model


def _post_json(url: str, payload: dict[str, object]) -> dict[str, object]:
    body = json.dumps(payload).encode("utf-8")
    req = Request(url, data=body, headers={"Content-Type": "application/json"}, method="POST")
    with urlopen(req, timeout=10) as resp:  # noqa: S310 - local service calls
        return json.loads(resp.read().decode("utf-8"))


def cmd_download_data(args: argparse.Namespace) -> None:
    RAW_DIR.mkdir(parents=True, exist_ok=True)
    tranco_local = Path(args.tranco_local) if args.tranco_local else None
    tranco_path = download_tranco(
        list_id=args.tranco_list_id,
        output_dir=RAW_DIR,
        fallback_local_csv=tranco_local,
    )
    urlhaus_path = download_urlhaus(output_dir=RAW_DIR)
    phishtank = download_phishtank(output_dir=RAW_DIR, enabled=args.enable_phishtank)
    print(f"Downloaded Tranco -> {tranco_path}")
    print(f"Downloaded URLhaus -> {urlhaus_path}")
    print(f"PhishTank -> {phishtank if phishtank else 'not enabled or unavailable'}")


def cmd_build_dataset(_: argparse.Namespace) -> None:
    result = build_labeled_dataset()
    print(
        f"Built dataset: benign={result.benign_count}, malicious={result.malicious_count}, "
        f"csv={result.labeled_csv_path}"
    )


def cmd_train_domain_risk(args: argparse.Namespace) -> None:
    path = Path(args.input_csv) if args.input_csv else (PROCESSED_DIR / "labeled_domains.csv")
    metrics = train_domain_risk_model(path)
    print(json.dumps(metrics, indent=2))


def cmd_train_anomaly(args: argparse.Namespace) -> None:
    sim_path = Path(args.sim_file) if args.sim_file else (SIMULATION_DIR / "sample.jsonl")
    events = [json.loads(line) for line in sim_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    domain_scores = {e["domain"]: (80.0 if "login" in e["domain"] else 10.0) for e in events}
    windows = aggregate_events_to_windows(events, domain_scores=domain_scores, window_minutes=5)
    metrics = train_anomaly_model(windows)
    print(json.dumps(metrics, indent=2))


def cmd_simulate(args: argparse.Namespace) -> None:
    out_path = Path(args.output) if args.output else (SIMULATION_DIR / "sample.jsonl")
    path = write_simulation_jsonl(path=out_path)
    print(f"Wrote simulation to {path}")


def _init_replay_db(path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(path)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS replay_events (
            ts TEXT NOT NULL,
            domain TEXT NOT NULL,
            rcode TEXT NOT NULL,
            risk_score REAL,
            risk_label TEXT
        );
        """
    )
    conn.commit()
    return conn


def cmd_replay(args: argparse.Namespace) -> None:
    sim_path = Path(args.file)
    events = [json.loads(line) for line in sim_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    service_base = args.service_url.rstrip("/")
    db = _init_replay_db(Path(args.sqlite)) if args.sqlite else None

    domain_scores: dict[str, float] = {}
    for event in events:
        domain_resp = _post_json(f"{service_base}/score/domain", {"domain": event["domain"]})
        domain_scores[event["domain"]] = float(domain_resp["risk_score"])
        print(
            f"[{event['ts']}] {event['domain']:<40} "
            f"{domain_resp['risk_label']:<18} score={domain_resp['risk_score']:.1f}"
        )
        if db is not None:
            db.execute(
                "INSERT INTO replay_events(ts, domain, rcode, risk_score, risk_label) VALUES (?, ?, ?, ?, ?)",
                (
                    event["ts"],
                    event["domain"],
                    event["rcode"],
                    float(domain_resp["risk_score"]),
                    str(domain_resp["risk_label"]),
                ),
            )

    windows = aggregate_events_to_windows(events, domain_scores=domain_scores, window_minutes=5)
    for win in windows:
        payload = {
            "window_start": win.window_start,
            "window_end": win.window_end,
            "queries_per_min": win.queries_per_min,
            "unique_domains": win.unique_domains,
            "nxdomain_rate": win.nxdomain_rate,
            "mean_domain_risk": win.mean_domain_risk,
            "high_risk_domain_ratio": win.high_risk_domain_ratio,
            "newly_seen_ratio": win.newly_seen_ratio,
            "periodicity_score": win.periodicity_score,
        }
        window_resp = _post_json(f"{service_base}/score/window", payload)
        print(
            f"ALERT {win.window_start} -> {window_resp['anomaly_label']} "
            f"(score={window_resp['anomaly_score']:.2f})"
        )
        print(f"  {window_resp['summary']}")
        if args.realtime:
            time.sleep(0.1)

    if db is not None:
        db.commit()
        db.close()
    print(f"Replay complete at {datetime.now().isoformat(timespec='seconds')}")


def cmd_live_monitor(args: argparse.Namespace) -> None:
    privacy = LivePrivacyConfig(
        hash_domains=args.hash_domains,
        hash_salt=args.hash_salt,
        exclude_patterns=args.exclude_pattern,
        retention_days=args.retention_days,
    )
    run_live_monitor(
        input_file=Path(args.input_file),
        output_csv=Path(args.output_csv),
        alerts_csv=Path(args.alerts_csv),
        privacy=privacy,
        poll_seconds=args.poll_seconds,
        window_minutes=args.window_minutes,
        once=args.once,
        start_at_end=args.start_at_end,
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="sentineldns")
    sub = parser.add_subparsers(dest="command", required=True)

    d = sub.add_parser("download-data")
    d.add_argument("--tranco-list-id", default="latest")
    d.add_argument("--tranco-local", default=None)
    d.add_argument("--enable-phishtank", action="store_true")
    d.set_defaults(func=cmd_download_data)

    b = sub.add_parser("build-dataset")
    b.set_defaults(func=cmd_build_dataset)

    t = sub.add_parser("train-domain-risk")
    t.add_argument("--input-csv", default=None)
    t.set_defaults(func=cmd_train_domain_risk)

    a = sub.add_parser("train-anomaly")
    a.add_argument("--sim-file", default=None)
    a.set_defaults(func=cmd_train_anomaly)

    s = sub.add_parser("simulate")
    s.add_argument("--output", default=None)
    s.set_defaults(func=cmd_simulate)

    r = sub.add_parser("replay")
    r.add_argument("--file", required=True)
    r.add_argument("--service-url", default="http://127.0.0.1:8787")
    r.add_argument("--realtime", action="store_true")
    r.add_argument("--sqlite", default="data/processed/replay.sqlite")
    r.set_defaults(func=cmd_replay)

    l = sub.add_parser("live-monitor")
    l.add_argument("--input-file", required=True)
    l.add_argument("--output-csv", default="data/processed/live_scored_events.csv")
    l.add_argument("--alerts-csv", default="data/processed/live_window_alerts.csv")
    l.add_argument("--poll-seconds", type=float, default=2.0)
    l.add_argument("--window-minutes", type=int, default=5)
    l.add_argument("--retention-days", type=int, default=14)
    l.add_argument("--exclude-pattern", action="append", default=[])
    l.add_argument("--hash-domains", action="store_true")
    l.add_argument("--hash-salt", default="sentineldns-local")
    l.add_argument("--start-at-end", action="store_true")
    l.add_argument("--once", action="store_true")
    l.set_defaults(func=cmd_live_monitor)

    return parser


def main() -> None:
    configure_logging()
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
