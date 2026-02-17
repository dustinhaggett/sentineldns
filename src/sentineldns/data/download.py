from __future__ import annotations

import csv
import io
import logging
import os
import zipfile
from pathlib import Path
from urllib.error import URLError
from urllib.request import Request, urlopen

from sentineldns.config import RAW_DIR

logger = logging.getLogger(__name__)

TRANC0_LATEST_URL = "https://tranco-list.eu/top-1m.csv.zip"
TRANC0_BY_ID_URL = "https://tranco-list.eu/{list_id}/top-1m.csv.zip"
URLHAUS_URL = "https://urlhaus.abuse.ch/downloads/text_online/"


def _fetch(url: str, timeout: int = 30) -> bytes:
    req = Request(url, headers={"User-Agent": "sentineldns-mvp/0.1"})
    with urlopen(req, timeout=timeout) as resp:  # noqa: S310 - controlled URLs
        return resp.read()


def download_tranco(
    list_id: str = "latest",
    output_dir: Path | None = None,
    fallback_local_csv: Path | None = None,
) -> Path:
    output_dir = output_dir or RAW_DIR
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / "tranco_top1m.csv"

    if fallback_local_csv and fallback_local_csv.exists():
        logger.info("Using local Tranco file: %s", fallback_local_csv)
        output_path.write_bytes(fallback_local_csv.read_bytes())
        return output_path

    url = TRANC0_LATEST_URL if list_id == "latest" else TRANC0_BY_ID_URL.format(list_id=list_id)
    logger.info("Downloading Tranco list from %s", url)
    try:
        payload = _fetch(url)
    except URLError as exc:
        if fallback_local_csv and fallback_local_csv.exists():
            logger.warning("Tranco download failed (%s), using local fallback", exc)
            output_path.write_bytes(fallback_local_csv.read_bytes())
            return output_path
        raise RuntimeError(
            "Failed to download Tranco list. Provide --tranco-local path as fallback."
        ) from exc

    with zipfile.ZipFile(io.BytesIO(payload), "r") as zf:
        names = zf.namelist()
        if not names:
            raise RuntimeError("Tranco zip download was empty")
        with zf.open(names[0], "r") as fh:
            content = fh.read()
            output_path.write_bytes(content)
    return output_path


def download_urlhaus(output_dir: Path | None = None) -> Path:
    output_dir = output_dir or RAW_DIR
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / "urlhaus_urls.txt"
    logger.info("Downloading URLhaus data from %s", URLHAUS_URL)
    payload = _fetch(URLHAUS_URL)
    output_path.write_bytes(payload)
    return output_path


def download_phishtank(output_dir: Path | None = None, enabled: bool = False) -> Path | None:
    if not enabled:
        return None
    output_dir = output_dir or RAW_DIR
    output_dir.mkdir(parents=True, exist_ok=True)
    endpoint = os.getenv(
        "PHISHTANK_URL",
        "https://data.phishtank.com/data/online-valid.csv",
    )
    output_path = output_dir / "phishtank.csv"
    try:
        payload = _fetch(endpoint)
    except URLError as exc:
        logger.warning("Skipping PhishTank integration (%s)", exc)
        return None
    output_path.write_bytes(payload)
    return output_path


def read_tranco_domains(csv_path: Path, limit: int = 100_000) -> list[str]:
    domains: list[str] = []
    with csv_path.open("r", encoding="utf-8", newline="") as fh:
        reader = csv.reader(fh)
        for row in reader:
            if not row:
                continue
            domain = row[-1].strip()
            if domain:
                domains.append(domain)
            if len(domains) >= limit:
                break
    return domains
