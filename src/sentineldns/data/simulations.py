from __future__ import annotations

import json
import random
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from sentineldns.config import SIMULATION_DIR

NORMAL_DOMAINS = [
    "apple.com",
    "developer.apple.com",
    "github.com",
    "news.ycombinator.com",
    "wikipedia.org",
    "cdn.jsdelivr.net",
    "nytimes.com",
    "netflix.com",
]

SUSPICIOUS_WORDS = ["verify", "secure", "account", "login", "wallet"]


@dataclass
class SimulateConfig:
    total_minutes: int = 45
    events_per_minute: int = 12
    incident_start_minute: int = 26
    incident_length_minutes: int = 8


def _random_dga_domain() -> str:
    left = "".join(random.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=14))
    tld = random.choice([".com", ".net", ".top", ".xyz"])
    return f"{left}{tld}"


def generate_simulation_events(config: SimulateConfig | None = None) -> list[dict[str, str]]:
    config = config or SimulateConfig()
    events: list[dict[str, str]] = []
    start_ts = datetime.now(UTC).replace(second=0, microsecond=0) - timedelta(
        minutes=config.total_minutes
    )

    for minute in range(config.total_minutes):
        current_ts = start_ts + timedelta(minutes=minute)
        in_incident = (
            config.incident_start_minute
            <= minute
            < (config.incident_start_minute + config.incident_length_minutes)
        )
        for _ in range(config.events_per_minute):
            if in_incident and random.random() < 0.65:
                domain = _random_dga_domain()
                if random.random() < 0.4:
                    domain = f"{random.choice(SUSPICIOUS_WORDS)}-{domain}"
                rcode = "NXDOMAIN" if random.random() < 0.35 else "NOERROR"
            else:
                domain = random.choice(NORMAL_DOMAINS)
                rcode = "NOERROR" if random.random() < 0.98 else "NXDOMAIN"
            events.append(
                {
                    "ts": (current_ts + timedelta(seconds=random.randint(0, 59))).isoformat(),
                    "domain": domain,
                    "rcode": rcode,
                    "qtype": random.choice(["A", "AAAA"]),
                }
            )
    events.sort(key=lambda e: e["ts"])
    return events


def write_simulation_jsonl(path: Path | None = None, config: SimulateConfig | None = None) -> Path:
    path = path or (SIMULATION_DIR / "sample.jsonl")
    path.parent.mkdir(parents=True, exist_ok=True)
    events = generate_simulation_events(config=config)
    with path.open("w", encoding="utf-8") as fh:
        for event in events:
            fh.write(json.dumps(event) + "\n")
    return path
