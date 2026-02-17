from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from datetime import datetime, timedelta

import numpy as np


@dataclass
class WindowStats:
    window_start: str
    window_end: str
    queries_per_min: float
    unique_domains: int
    nxdomain_rate: float
    mean_domain_risk: float
    high_risk_domain_ratio: float
    newly_seen_ratio: float
    periodicity_score: float


def periodicity_score(values: list[float]) -> float:
    arr = np.array(values, dtype=np.float64)
    if arr.size < 4:
        return 0.0
    arr = arr - arr.mean()
    if np.allclose(arr, 0):
        return 0.0
    corr = np.correlate(arr, arr, mode="full")[arr.size - 1 :]
    if corr.size < 3:
        return 0.0
    baseline = float(np.mean(np.abs(corr[1:]))) + 1e-9
    peak = float(np.max(corr[1:]))
    return max(0.0, peak / baseline)


def aggregate_events_to_windows(
    events: list[dict[str, str]],
    domain_scores: dict[str, float],
    window_minutes: int = 5,
) -> list[WindowStats]:
    if not events:
        return []
    parsed = sorted(events, key=lambda e: e["ts"])
    seen_history: deque[str] = deque(maxlen=50_000)
    seen_set = set()
    windows: list[WindowStats] = []
    i = 0
    while i < len(parsed):
        start = datetime.fromisoformat(parsed[i]["ts"])
        end = start + timedelta(minutes=window_minutes)
        bucket: list[dict[str, str]] = []
        while i < len(parsed) and datetime.fromisoformat(parsed[i]["ts"]) < end:
            bucket.append(parsed[i])
            i += 1
        if not bucket:
            continue

        domains = [item["domain"] for item in bucket]
        unique_domains = set(domains)
        nxdomain_count = sum(1 for item in bucket if item.get("rcode") == "NXDOMAIN")
        risks = [domain_scores.get(domain, 0.0) for domain in domains]
        high_risk = [score for score in risks if score > 70]

        newly_seen = 0
        for domain in unique_domains:
            if domain not in seen_set:
                newly_seen += 1
                seen_set.add(domain)
                seen_history.append(domain)
        if len(seen_history) == seen_history.maxlen:
            removed = seen_history[0]
            if removed in seen_set:
                seen_set.remove(removed)

        windows.append(
            WindowStats(
                window_start=start.isoformat(),
                window_end=end.isoformat(),
                queries_per_min=len(bucket) / float(window_minutes),
                unique_domains=len(unique_domains),
                nxdomain_rate=nxdomain_count / float(max(len(bucket), 1)),
                mean_domain_risk=float(np.mean(risks)) if risks else 0.0,
                high_risk_domain_ratio=len(high_risk) / float(max(len(risks), 1)),
                newly_seen_ratio=newly_seen / float(max(len(unique_domains), 1)),
                periodicity_score=0.0,
            )
        )

    periodic_inputs = [w.queries_per_min for w in windows]
    pscore = periodicity_score(periodic_inputs)
    for w in windows:
        w.periodicity_score = pscore
    return windows


def window_stats_to_matrix(stats: list[WindowStats]) -> np.ndarray:
    return np.array(
        [
            [
                s.queries_per_min,
                float(s.unique_domains),
                s.nxdomain_rate,
                s.mean_domain_risk,
                s.high_risk_domain_ratio,
                s.newly_seen_ratio,
                s.periodicity_score,
            ]
            for s in stats
        ],
        dtype=np.float64,
    )
