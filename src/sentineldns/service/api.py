from __future__ import annotations

import logging

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from sentineldns.features.window_features import WindowStats
from sentineldns.models.anomaly import AnomalyBundle, load_anomaly_bundle, score_window
from sentineldns.models.domain_risk import DomainRiskModelBundle, load_domain_risk_bundle, score_domain
from sentineldns.models.explain import explain_anomaly_result, explain_domain_result
from sentineldns.service.schemas import (
    DomainScoreRequest,
    DomainScoreResponse,
    WindowScoreRequest,
    WindowScoreResponse,
)

logger = logging.getLogger(__name__)

app = FastAPI(title="SentinelDNS Local Inference Service", version="0.1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost", "http://127.0.0.1", "http://localhost:*", "http://127.0.0.1:*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

DOMAIN_BUNDLE: DomainRiskModelBundle | None = None
ANOMALY_BUNDLE: AnomalyBundle | None = None


def _load_models() -> None:
    global DOMAIN_BUNDLE, ANOMALY_BUNDLE
    if DOMAIN_BUNDLE is None:
        DOMAIN_BUNDLE = load_domain_risk_bundle()
    if ANOMALY_BUNDLE is None:
        ANOMALY_BUNDLE = load_anomaly_bundle()


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/score/domain", response_model=DomainScoreResponse)
def score_domain_endpoint(req: DomainScoreRequest) -> DomainScoreResponse:
    try:
        _load_models()
        assert DOMAIN_BUNDLE is not None
        result = score_domain(req.domain, DOMAIN_BUNDLE)
        explained = explain_domain_result(result["risk_score"], result["reason_tags"])
        if explained["category"] == "Likely Malicious":
            result["risk_label"] = "Likely Malicious"
        return DomainScoreResponse(**result)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=503, detail="Model artifacts missing. Run training first.") from exc
    except Exception as exc:
        logger.exception("Failed to score domain")
        raise HTTPException(status_code=500, detail=f"Domain scoring failed: {exc}") from exc


@app.post("/score/window", response_model=WindowScoreResponse)
def score_window_endpoint(req: WindowScoreRequest) -> WindowScoreResponse:
    try:
        _load_models()
        assert ANOMALY_BUNDLE is not None
        stats = WindowStats(
            window_start=req.window_start,
            window_end=req.window_end,
            queries_per_min=req.queries_per_min,
            unique_domains=req.unique_domains,
            nxdomain_rate=req.nxdomain_rate,
            mean_domain_risk=req.mean_domain_risk,
            high_risk_domain_ratio=req.high_risk_domain_ratio,
            newly_seen_ratio=req.newly_seen_ratio,
            periodicity_score=req.periodicity_score,
        )
        result = score_window(stats, ANOMALY_BUNDLE)
        explained = explain_anomaly_result(
            anomaly_score=result["anomaly_score"],
            reason_tags=result["reason_tags"],
            queries_per_min=req.queries_per_min,
            nxdomain_rate=req.nxdomain_rate,
        )
        return WindowScoreResponse(
            anomaly_score=result["anomaly_score"],
            anomaly_label=result["anomaly_label"],
            summary=explained["summary"],
            reason_tags=explained["reason_tags"],
            recommended_action=explained["recommended_action"],
            model_version=result["model_version"],
        )
    except FileNotFoundError as exc:
        raise HTTPException(status_code=503, detail="Model artifacts missing. Run training first.") from exc
    except Exception as exc:
        logger.exception("Failed to score window")
        raise HTTPException(status_code=500, detail=f"Window scoring failed: {exc}") from exc
