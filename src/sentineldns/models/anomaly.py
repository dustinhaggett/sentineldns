from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest

from sentineldns.config import get_anomaly_artifact_dir
from sentineldns.features.window_features import WindowStats, window_stats_to_matrix


@dataclass
class AnomalyBundle:
    model: IsolationForest | None
    metadata: dict[str, Any]


def train_anomaly_model(
    normal_stats: list[WindowStats],
    artifact_dir: Path | None = None,
    contamination: float = 0.05,
) -> dict[str, Any]:
    artifact_dir = artifact_dir or get_anomaly_artifact_dir()
    artifact_dir.mkdir(parents=True, exist_ok=True)
    X = window_stats_to_matrix(normal_stats)
    if len(X) < 5:
        raise ValueError("Need at least 5 windows to train anomaly model")

    model = IsolationForest(
        n_estimators=200,
        contamination=contamination,
        random_state=42,
    )
    model.fit(X)
    decision = model.decision_function(X)
    mean = float(np.mean(decision))
    std = float(np.std(decision) + 1e-9)

    metadata = {
        "model_version": datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ"),
        "contamination": contamination,
        "train_windows": int(len(normal_stats)),
        "decision_mean": mean,
        "decision_std": std,
        "features": [
            "queries_per_min",
            "unique_domains",
            "nxdomain_rate",
            "mean_domain_risk",
            "high_risk_domain_ratio",
            "newly_seen_ratio",
            "periodicity_score",
        ],
        "fallback_method": "zscore",
    }
    joblib.dump(model, artifact_dir / "model.joblib")
    (artifact_dir / "metadata.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    return metadata


def load_anomaly_bundle(artifact_dir: Path | None = None) -> AnomalyBundle:
    artifact_dir = artifact_dir or get_anomaly_artifact_dir()
    metadata = json.loads((artifact_dir / "metadata.json").read_text(encoding="utf-8"))
    model_path = artifact_dir / "model.joblib"
    model = joblib.load(model_path) if model_path.exists() else None
    return AnomalyBundle(model=model, metadata=metadata)


def score_window(stats: WindowStats, bundle: AnomalyBundle) -> dict[str, Any]:
    X = window_stats_to_matrix([stats])
    if bundle.model is not None:
        raw = float(bundle.model.decision_function(X)[0])
        mean = float(bundle.metadata.get("decision_mean", 0.0))
        std = float(bundle.metadata.get("decision_std", 1.0))
    else:
        raw = float(stats.nxdomain_rate + stats.high_risk_domain_ratio + stats.newly_seen_ratio)
        mean = 0.2
        std = 0.1

    z = (mean - raw) / max(std, 1e-9)
    anomaly_score = float(np.clip(1 / (1 + np.exp(-z)), 0, 1))
    if anomaly_score < 0.45:
        label = "Normal"
    elif anomaly_score < 0.75:
        label = "Unusual"
    else:
        label = "Likely Compromise"

    reason_tags: list[str] = []
    if stats.nxdomain_rate > 0.2:
        reason_tags.append("elevated NXDOMAIN rate")
    if stats.high_risk_domain_ratio > 0.25:
        reason_tags.append("many high-risk domains")
    if stats.newly_seen_ratio > 0.6:
        reason_tags.append("many newly seen domains")
    if stats.periodicity_score > 2.0:
        reason_tags.append("periodic query pattern detected")
    if not reason_tags:
        reason_tags.append("traffic appears within expected range")

    return {
        "anomaly_score": anomaly_score,
        "anomaly_label": label,
        "reason_tags": reason_tags[:5],
        "model_version": bundle.metadata.get("model_version", "unknown"),
    }
