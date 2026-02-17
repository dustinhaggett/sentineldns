from __future__ import annotations

from pydantic import BaseModel, Field


class DomainScoreRequest(BaseModel):
    domain: str = Field(min_length=1, max_length=253)


class DomainScoreResponse(BaseModel):
    domain: str
    risk_score: float
    risk_label: str
    reason_tags: list[str]
    model_version: str
    thresholds: dict[str, float]


class WindowScoreRequest(BaseModel):
    window_start: str
    window_end: str
    queries_per_min: float = Field(ge=0)
    unique_domains: int = Field(ge=0)
    nxdomain_rate: float = Field(ge=0, le=1)
    mean_domain_risk: float = Field(ge=0, le=100)
    high_risk_domain_ratio: float = Field(ge=0, le=1)
    newly_seen_ratio: float = Field(ge=0, le=1)
    periodicity_score: float = Field(ge=0)


class WindowScoreResponse(BaseModel):
    anomaly_score: float
    anomaly_label: str
    summary: str
    reason_tags: list[str]
    recommended_action: str
    model_version: str
