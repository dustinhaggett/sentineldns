from __future__ import annotations

import csv
import logging
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

import pandas as pd

from sentineldns.config import PROCESSED_DIR, RAW_DIR
from sentineldns.data.download import read_tranco_domains
from sentineldns.data.normalize import DomainRecord, normalize_domain

logger = logging.getLogger(__name__)


@dataclass
class BuildResult:
    benign_count: int
    malicious_count: int
    labeled_csv_path: Path


def _read_urlhaus_urls(path: Path) -> list[str]:
    urls: list[str] = []
    if not path.exists():
        return urls
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        urls.append(line)
    return urls


def _read_phishtank_urls(path: Path | None) -> list[str]:
    if path is None or not path.exists():
        return []
    values: list[str] = []
    with path.open("r", encoding="utf-8", errors="ignore", newline="") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            maybe_url = row.get("url") or row.get("phish_url") or ""
            if maybe_url:
                values.append(maybe_url)
    return values


def _to_record(raw: str, remove_www: bool = True) -> DomainRecord | None:
    return normalize_domain(raw, remove_www=remove_www, include_etld1=False)


def build_labeled_dataset(
    raw_dir: Path | None = None,
    processed_dir: Path | None = None,
    remove_www: bool = True,
) -> BuildResult:
    raw_dir = raw_dir or RAW_DIR
    processed_dir = processed_dir or PROCESSED_DIR
    processed_dir.mkdir(parents=True, exist_ok=True)

    tranco_csv = raw_dir / "tranco_top1m.csv"
    urlhaus_txt = raw_dir / "urlhaus_urls.txt"
    phishtank_csv = raw_dir / "phishtank.csv"

    benign_raw = read_tranco_domains(tranco_csv) if tranco_csv.exists() else []
    malicious_raw = _read_urlhaus_urls(urlhaus_txt) + _read_phishtank_urls(
        phishtank_csv if phishtank_csv.exists() else None
    )

    benign_records = [
        rec
        for raw in benign_raw
        for rec in [_to_record(raw, remove_www=remove_www)]
        if rec is not None
    ]
    malicious_records = [
        rec
        for raw in malicious_raw
        for rec in [_to_record(urlparse(raw).hostname or raw, remove_www=remove_www)]
        if rec is not None
    ]

    benign_unique = {r.normalized_domain: r for r in benign_records}
    malicious_unique = {r.normalized_domain: r for r in malicious_records}

    overlap = set(benign_unique.keys()) & set(malicious_unique.keys())
    for key in overlap:
        benign_unique.pop(key, None)

    benign_path = processed_dir / "benign_domains.txt"
    malicious_path = processed_dir / "malicious_domains.txt"
    labeled_path = processed_dir / "labeled_domains.csv"

    benign_path.write_text(
        "\n".join(sorted(benign_unique.keys())) + ("\n" if benign_unique else ""),
        encoding="utf-8",
    )
    malicious_path.write_text(
        "\n".join(sorted(malicious_unique.keys())) + ("\n" if malicious_unique else ""),
        encoding="utf-8",
    )

    rows: list[dict[str, object]] = []
    for rec in benign_unique.values():
        rows.append(
            {
                "domain": rec.normalized_domain,
                "label": 0,
                "source": "tranco",
                "raw_value": rec.raw_value,
            }
        )
    for rec in malicious_unique.values():
        rows.append(
            {
                "domain": rec.normalized_domain,
                "label": 1,
                "source": "urlhaus_or_phishtank",
                "raw_value": rec.raw_value,
            }
        )
    df = pd.DataFrame(rows).sort_values(["label", "domain"]).reset_index(drop=True)
    df.to_csv(labeled_path, index=False)
    logger.info("Wrote %s rows to %s", len(df), labeled_path)

    return BuildResult(
        benign_count=len(benign_unique),
        malicious_count=len(malicious_unique),
        labeled_csv_path=labeled_path,
    )
