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
from sklearn.metrics import confusion_matrix, precision_recall_curve
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


KNOWN_BENIGN_EXACT = {
    "apple.com",
    "developer.apple.com",
    "github.com",
    "news.ycombinator.com",
    "wikipedia.org",
    "cdn.jsdelivr.net",
    "nytimes.com",
    "netflix.com",
}
KNOWN_BENIGN_SUFFIXES = {
    ".apple.com",
}
SUSPICIOUS_TLDS = {
    "top",
    "xyz",
    "zip",
    "click",
    "shop",
    "gq",
    "tk",
    "fit",
    "rest",
    "country",
    "mom",
    "monster",
    "homes",
}


def _is_known_benign_domain(domain: str) -> bool:
    if domain in KNOWN_BENIGN_EXACT:
        return True
    return any(domain.endswith(suffix) for suffix in KNOWN_BENIGN_SUFFIXES)


def select_threshold_low_fpr(y_true: np.ndarray, y_score: np.ndarray, target_fpr: float = 0.01) -> float:
    """Estimate a stable threshold by bounding to the benign score percentile."""
    benign_scores = y_score[y_true == 0]
    if benign_scores.size == 0:
        return 0.9
    quantile = float(np.quantile(benign_scores, 1.0 - target_fpr))
    # Keep threshold practical for user-facing labels.
    return float(np.clip(quantile, 0.55, 0.98))


def _apply_score_guardrails(
    domain: str,
    score: float,
    reason_tags: list[str],
    scalar_map: dict[str, float],
) -> float:
    adjusted = score
    tld = domain.rsplit(".", 1)[-1] if "." in domain else domain
    suspicious_tld = tld in SUSPICIOUS_TLDS

    if _is_known_benign_domain(domain):
        # Keep benign domains low-risk but preserve score variation.
        soft_cap = float(np.clip(14.0 + (0.22 * adjusted), 14.0, 34.5))
        adjusted = min(adjusted, soft_cap)

    has_phishing_signals = (
        "contains phishing-like words" in reason_tags
        or "looks similar to a popular brand" in reason_tags
        or scalar_map["brand_edit_distance_min"] <= 2
        or scalar_map["has_suspicious_words"] >= 1
    )
    looks_random = scalar_map["entropy"] > 3.5 and scalar_map["digit_ratio"] > 0.15

    if not _is_known_benign_domain(domain):
        signal_strength = 0
        if has_phishing_signals:
            signal_strength += 2
        if looks_random:
            signal_strength += 1
        if suspicious_tld:
            signal_strength += 1
        if scalar_map["brand_edit_distance_min"] <= 2:
            signal_strength += 1

        dynamic_floor = 0.0
        if signal_strength >= 2:
            dynamic_floor = 34.0 + (6.0 * float(signal_strength - 1))
        if has_phishing_signals:
            dynamic_floor = max(dynamic_floor, 42.0)
        if looks_random and suspicious_tld:
            dynamic_floor = max(dynamic_floor, 38.0)
        adjusted = max(adjusted, dynamic_floor)

    return float(np.clip(adjusted, 0.0, 100.0))


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
        "known_benign_exact_count": len(KNOWN_BENIGN_EXACT),
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
    domain = domain.strip().lower()
    X, _, _ = build_domain_feature_matrix([domain], vectorizer=bundle.vectorizer)
    prob = float(bundle.model.predict_proba(X)[0, 1])
    threshold = float(bundle.metadata.get("threshold", 0.8))
    scalars = scalar_features(domain)
    coef = getattr(bundle.model, "coef_", np.array([]))
    coef_tail: np.ndarray | None = None
    if coef.size:
        coef_tail = coef[0][-len(SCALAR_FEATURE_NAMES) :]
    reasons = scalar_reason_tags(scalars, coef_tail=coef_tail)

    score = round(_apply_score_guardrails(domain, prob * 100.0, reasons, scalars), 2)
    likely_cutoff = max(75.0, min(95.0, threshold * 100.0))
    if score < 35:
        label = "Normal"
    elif score < likely_cutoff:
        label = "Suspicious"
    else:
        label = "Likely Malicious"
    return {
        "domain": domain,
        "risk_score": score,
        "risk_label": label,
        "reason_tags": reasons,
        "thresholds": {"decision_threshold_probability": threshold},
        "model_version": bundle.metadata.get("model_version", "unknown"),
    }
