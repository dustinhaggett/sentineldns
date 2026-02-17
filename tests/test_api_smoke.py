from __future__ import annotations

import json
from pathlib import Path

import pandas as pd
from fastapi.testclient import TestClient

from sentineldns.data.simulations import SimulateConfig, generate_simulation_events
from sentineldns.features.window_features import aggregate_events_to_windows
from sentineldns.models.anomaly import train_anomaly_model
from sentineldns.models.domain_risk import train_domain_risk_model


def _prepare_artifacts(tmp_path: Path) -> None:
    labeled = pd.DataFrame(
        {
            "domain": [
                "apple.com",
                "google.com",
                "netflix.com",
                "login-paypal-secure.top",
                "verify-microsoft-account.net",
                "wallet-update-security.xyz",
            ],
            "label": [0, 0, 0, 1, 1, 1],
            "source": ["test"] * 6,
            "raw_value": ["test"] * 6,
        }
    )
    processed = tmp_path / "processed"
    processed.mkdir(parents=True, exist_ok=True)
    csv_path = processed / "labeled_domains.csv"
    labeled.to_csv(csv_path, index=False)

    artifacts = tmp_path / "artifacts"
    domain_dir = artifacts / "domain_risk"
    anomaly_dir = artifacts / "anomaly"
    train_domain_risk_model(csv_path, artifact_dir=domain_dir)

    events = generate_simulation_events(SimulateConfig(total_minutes=25, events_per_minute=8))
    domain_scores = {e["domain"]: (80.0 if "login" in e["domain"] else 12.0) for e in events}
    windows = aggregate_events_to_windows(events, domain_scores)
    train_anomaly_model(windows, artifact_dir=anomaly_dir)


def test_health_and_domain_score_smoke(tmp_path: Path, monkeypatch) -> None:
    _prepare_artifacts(tmp_path)
    monkeypatch.setenv("SENTINELDNS_ARTIFACT_DIR", str(tmp_path / "artifacts"))

    from sentineldns.service.api import app

    client = TestClient(app)
    health = client.get("/health")
    assert health.status_code == 200
    assert health.json()["status"] == "ok"

    scored = client.post("/score/domain", json={"domain": "login-google-support.top"})
    assert scored.status_code == 200
    payload = scored.json()
    assert 0 <= payload["risk_score"] <= 100
    assert payload["risk_label"] in {"Normal", "Suspicious", "Likely Malicious"}
    assert isinstance(payload["reason_tags"], list)
    # Guardrail: phishing-like lexical indicators should not remain Normal.
    assert payload["risk_label"] != "Normal"

    benign = client.post("/score/domain", json={"domain": "news.ycombinator.com"})
    assert benign.status_code == 200
    benign_payload = benign.json()
    # Guardrail: known stable benign domains should not score as likely malicious.
    assert benign_payload["risk_label"] != "Likely Malicious"

    random_cheap_tld = client.post("/score/domain", json={"domain": "i6sbhgmo1gp6ol.top"})
    assert random_cheap_tld.status_code == 200
    random_payload = random_cheap_tld.json()
    # Guardrail: random-looking cheap-TLD domains should not look fully benign.
    assert random_payload["risk_score"] >= 35.0

    window_req = {
        "window_start": "2026-01-01T00:00:00+00:00",
        "window_end": "2026-01-01T00:05:00+00:00",
        "queries_per_min": 15.0,
        "unique_domains": 40,
        "nxdomain_rate": 0.3,
        "mean_domain_risk": 62.0,
        "high_risk_domain_ratio": 0.4,
        "newly_seen_ratio": 0.75,
        "periodicity_score": 2.1,
    }
    win = client.post("/score/window", json=window_req)
    assert win.status_code == 200
    win_payload = win.json()
    assert 0 <= win_payload["anomaly_score"] <= 1
    assert win_payload["anomaly_label"] in {"Normal", "Unusual", "Likely Compromise"}
