from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import confusion_matrix, precision_recall_curve, roc_curve
from sklearn.model_selection import train_test_split

from sentineldns.config import get_domain_artifact_dir
from sentineldns.features.domain_features import (
    SCALAR_FEATURE_NAMES,
    build_domain_feature_matrix,
    scalar_features,
    scalar_reason_tags,
)


@dataclass
class DomainRiskModelBundle:
    model: LogisticRegression
    vectorizer: Any
    metadata: dict[str, Any]


def select_threshold_low_fpr(y_true: np.ndarray, y_score: np.ndarray, target_fpr: float = 0.01) -> float:
    fpr, _, thresholds = roc_curve(y_true, y_score)
    candidates = [
        float(thr)
        for fp, thr in zip(fpr, thresholds, strict=True)
        if fp <= target_fpr and np.isfinite(thr)
    ]
    if not candidates:
        return 0.9
    return float(max(candidates))


def train_domain_risk_model(
    labeled_csv_path: Path,
    artifact_dir: Path | None = None,
    random_state: int = 42,
) -> dict[str, Any]:
    artifact_dir = artifact_dir or get_domain_artifact_dir()
    artifact_dir.mkdir(parents=True, exist_ok=True)

    df = pd.read_csv(labeled_csv_path)
    if df.empty:
        raise ValueError("Labeled dataset is empty")
    domains = df["domain"].astype(str).tolist()
    y = df["label"].astype(int).to_numpy()

    X, vectorizer, _ = build_domain_feature_matrix(domains)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=random_state, stratify=y
    )
    model = LogisticRegression(
        solver="liblinear",
        class_weight="balanced",
        max_iter=500,
        random_state=random_state,
    )
    model.fit(X_train, y_train)

    probs = model.predict_proba(X_test)[:, 1]
    threshold = select_threshold_low_fpr(y_test, probs, target_fpr=0.01)
    preds = (probs >= threshold).astype(int)

    precision, recall, _ = precision_recall_curve(y_test, probs)
    cm = confusion_matrix(y_test, preds).tolist()

    metadata = {
        "model_version": datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ"),
        "train_rows": int(len(y_train)),
        "test_rows": int(len(y_test)),
        "threshold": threshold,
        "target_fpr": 0.01,
        "scalar_feature_names": SCALAR_FEATURE_NAMES,
        "precision_curve_points": int(len(precision)),
        "recall_curve_points": int(len(recall)),
        "confusion_matrix": cm,
    }
    joblib.dump(model, artifact_dir / "model.joblib")
    joblib.dump(vectorizer, artifact_dir / "vectorizer.joblib")
    (artifact_dir / "metadata.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    return metadata


def load_domain_risk_bundle(artifact_dir: Path | None = None) -> DomainRiskModelBundle:
    artifact_dir = artifact_dir or get_domain_artifact_dir()
    model = joblib.load(artifact_dir / "model.joblib")
    vectorizer = joblib.load(artifact_dir / "vectorizer.joblib")
    metadata = json.loads((artifact_dir / "metadata.json").read_text(encoding="utf-8"))
    return DomainRiskModelBundle(model=model, vectorizer=vectorizer, metadata=metadata)


def score_domain(domain: str, bundle: DomainRiskModelBundle) -> dict[str, Any]:
    X, _, _ = build_domain_feature_matrix([domain], vectorizer=bundle.vectorizer)
    prob = float(bundle.model.predict_proba(X)[0, 1])
    threshold = float(bundle.metadata.get("threshold", 0.8))
    score = round(prob * 100, 2)
    if score < 35:
        label = "Normal"
    elif score < 75:
        label = "Suspicious"
    else:
        label = "Likely Malicious"

    scalars = scalar_features(domain)
    coef = getattr(bundle.model, "coef_", np.array([]))
    coef_tail: np.ndarray | None = None
    if coef.size:
        coef_tail = coef[0][-len(SCALAR_FEATURE_NAMES) :]
    reasons = scalar_reason_tags(scalars, coef_tail=coef_tail)
    return {
        "domain": domain,
        "risk_score": score,
        "risk_label": label,
        "reason_tags": reasons,
        "thresholds": {"decision_threshold_probability": threshold},
        "model_version": bundle.metadata.get("model_version", "unknown"),
    }
