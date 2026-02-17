from __future__ import annotations

import os
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
DATA_DIR = REPO_ROOT / "data"
RAW_DIR = DATA_DIR / "raw"
PROCESSED_DIR = DATA_DIR / "processed"
SIMULATION_DIR = DATA_DIR / "simulations"
ARTIFACTS_DIR = Path(os.getenv("SENTINELDNS_ARTIFACT_DIR", DATA_DIR / "artifacts"))

DOMAIN_ARTIFACT_DIR = ARTIFACTS_DIR / "domain_risk"
ANOMALY_ARTIFACT_DIR = ARTIFACTS_DIR / "anomaly"

DEFAULT_SERVICE_HOST = "127.0.0.1"
DEFAULT_SERVICE_PORT = 8787


def get_artifacts_dir() -> Path:
    return Path(os.getenv("SENTINELDNS_ARTIFACT_DIR", DATA_DIR / "artifacts"))


def get_domain_artifact_dir() -> Path:
    return get_artifacts_dir() / "domain_risk"


def get_anomaly_artifact_dir() -> Path:
    return get_artifacts_dir() / "anomaly"
