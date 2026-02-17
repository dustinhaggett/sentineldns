# SentinelDNS MVP — Repo Build Spec (for Codex)

You are Codex. Generate a complete, runnable repository implementing the MVP described below. Prioritize correctness, simplicity, and a polished demo. Provide code + instructions + sensible defaults. The repo must run end-to-end on macOS without cloud services.

## One-line Product
A macOS app that watches DNS activity and uses ML to flag suspicious behavior, then explains it in plain English for non-technical users.

---

# 0) MVP Scope (non-negotiable)

## Must ship
1) **Training pipeline** (Python) that builds a labeled dataset of domains:
   - benign domains from Tranco list
   - malicious/phishing domains extracted from URL feeds (URLhaus; optionally PhishTank)
2) **Domain risk model** (supervised) trained on domain-string features.
3) **Anomaly detector** (unsupervised) over time-window aggregates of DNS events.
4) **Local inference service** (FastAPI) that takes:
   - a domain string → returns risk_score + reasons
   - a time-window stats object → returns anomaly_score + reasons
5) **macOS app skeleton** (SwiftUI) that:
   - shows status: Normal / Unusual / Likely Compromise
   - shows latest alerts with plain-English explanations
   - shows recent domains with category + score
   - calls the local inference service for scoring
6) **Simulated incident mode** for guaranteed demo:
   - replays suspicious DNS-like events from a local file so alerts trigger even on a clean device
7) **Evaluation notebook** with PR curve, confusion matrix, and false-positive analysis.
8) **Clean README** with setup, demo steps, limitations, and roadmap.

## Nice-to-have (only if time remains)
- Core ML export
- DNS capture via NetworkExtension DNS proxy (full system interception)
- Domain blocking in proxy

## Out of scope for MVP
- full packet inspection
- iOS/Android
- router deployment
- per-app firewall prompts

---

# 1) Repository Layout

Create this structure:

sentineldns/
  README.md
  LICENSE (MIT)
  .gitignore
  pyproject.toml
  Makefile

  data/
    raw/                 # downloaded source feeds
    processed/           # cleaned domain lists, labels
    simulations/         # simulated DNS event streams
    artifacts/           # trained models, encoders, metadata

  notebooks/
    01_domain_risk_train_eval.ipynb
    02_anomaly_train_eval.ipynb

  src/
    sentineldns/
      __init__.py
      config.py
      logging_utils.py

      data/
        __init__.py
        download.py
        normalize.py
        build_dataset.py
        simulations.py

      features/
        __init__.py
        domain_features.py
        window_features.py

      models/
        __init__.py
        domain_risk.py
        anomaly.py
        export.py
        explain.py

      service/
        __init__.py
        api.py
        schemas.py
        run.py

      cli/
        __init__.py
        main.py

  apps/
    macos/
      SentinelDNS.xcodeproj (or Swift Package + Xcode project)
      SentinelDNS/
        App.swift
        Views/
          DashboardView.swift
          AlertsView.swift
          ActivityView.swift
          SettingsView.swift
        Models/
          APIClient.swift
          DTOs.swift
        Resources/
          SampleSimulatedEvents.jsonl

  tests/
    test_normalize.py
    test_domain_features.py
    test_api_smoke.py

---

# 2) Data Sources & Download Rules

Implement downloads with clear licensing notes and graceful fallbacks.

## Benign domains
- Tranco list: download latest list. Provide a CLI flag to specify a Tranco list ID OR download "latest".
- If direct download fails, allow user to provide a local Tranco CSV file path.

## Malicious/phishing URLs
- URLhaus plain-text URL list (one URL per line). Extract hostnames/domains.
- Optional: PhishTank (user may need an API key/login). Provide integration behind an optional flag and environment variables. Do not break if absent.

## Normalization requirements (critical)
For every extracted domain:
- lowercase
- strip trailing dot
- remove leading "www." ONLY as a configurable option (default: remove)
- IDNA handling: convert punycode to ASCII form consistently (store both original and normalized)
- validate domain format; drop invalid
- optionally compute eTLD+1 if publicsuffix2 is available; otherwise skip
- deduplicate

Output:
- data/processed/benign_domains.txt
- data/processed/malicious_domains.txt
- data/processed/labeled_domains.csv with columns:
  domain, label, source, raw_value

---

# 3) Feature Engineering

## Domain-string features (for supervised model)
Implement deterministic features in src/sentineldns/features/domain_features.py:

Scalar features:
- length
- num_labels
- tld (one-hot via hashing OR keep as string feature)
- digit_ratio
- hyphen_count
- vowel_ratio
- entropy (Shannon entropy over chars)
- punycode_flag (starts with xn-- in any label)
- has_suspicious_words flag using small list: ["login","verify","secure","account","update","bank","wallet","support"]
- brand_edit_distance_min: minimum Levenshtein distance to a small curated brand list: ["google","apple","microsoft","paypal","amazon","facebook","instagram","netflix"]

Text features:
- character n-grams (3-5) via HashingVectorizer (no vocabulary file), or CountVectorizer with max_features=50k (but hashing preferred).

Return:
- X matrix
- feature_names metadata
- a function to compute "reason tags" based on top contributing scalar features + model coefficients for linear model

## Time-window features (for anomaly model)
Given DNS event stream aggregated into windows:
- queries_per_min
- unique_domains
- nxdomain_rate
- mean_domain_risk
- high_risk_domain_ratio (risk_score > threshold)
- newly_seen_ratio (domain not seen in last 24h in the local store)
- periodicity_score (simple: ratio of top autocorrelation peak to baseline)

---

# 4) Models

## Supervised domain risk model
Implement in src/sentineldns/models/domain_risk.py

Baseline (required):
- LogisticRegression (liblinear or saga), class_weight="balanced"
Alternative:
- LightGBM if installed; otherwise stay with sklearn.

Training:
- stratified split
- handle class imbalance
- threshold selection:
  - pick threshold that targets low false positives (e.g., FPR <= 1%) and report achieved precision/recall

Export:
- save model + vectorizer + metadata to data/artifacts/domain_risk/
  - model.joblib
  - vectorizer.joblib
  - metadata.json (thresholds, training date, dataset sizes, feature params)

## Unsupervised anomaly model
Implement in src/sentineldns/models/anomaly.py

Baseline:
- IsolationForest with contamination tuned on simulated normal data
Also support:
- simple z-score threshold fallback

Export:
- data/artifacts/anomaly/
  - model.joblib
  - metadata.json

---

# 5) Explainability (plain English)

Implement src/sentineldns/models/explain.py

Given:
- domain risk result (score + feature values)
Return:
- category: Normal / Ads-Tracking / Suspicious / Likely Malicious (simple rules using score bands)
- reason_tags: 2-5 short strings, e.g.:
  - "rare-looking domain"
  - "high randomness in name"
  - "looks similar to a popular brand"
  - "uses punycode characters"
  - "contains phishing-like words"

Given:
- anomaly result (score + window stats)
Return:
- summary: 2-4 sentences in calm tone
- recommended_action: one of:
  - "No action needed"
  - "Keep an eye on it"
  - "Run a malware scan and change passwords if you entered credentials recently"
  - "Disconnect from network and investigate immediately"

Important:
- Never claim certainty ("you are hacked"). Use "possible", "suspicious", "consistent with".

---

# 6) Local Inference Service (FastAPI)

Implement src/sentineldns/service/api.py with endpoints:

GET /health
- returns ok

POST /score/domain
Request JSON:
{
  "domain": "example.com"
}
Response JSON:
{
  "domain": "...",
  "risk_score": 0-100,
  "risk_label": "Normal|Suspicious|Likely Malicious",
  "reason_tags": ["..."],
  "model_version": "...",
  "thresholds": {...}
}

POST /score/window
Request JSON:
{
  "window_start": "ISO8601",
  "window_end": "ISO8601",
  "queries_per_min": float,
  "unique_domains": int,
  "nxdomain_rate": float,
  "mean_domain_risk": float,
  "high_risk_domain_ratio": float,
  "newly_seen_ratio": float,
  "periodicity_score": float
}
Response JSON:
{
  "anomaly_score": 0-1,
  "anomaly_label": "Normal|Unusual|Likely Compromise",
  "summary": "plain english text",
  "reason_tags": ["..."],
  "recommended_action": "...",
  "model_version": "..."
}

Service requirements:
- loads models from data/artifacts by default
- supports env var SENTINELDNS_ARTIFACT_DIR
- includes CORS enabled for localhost app
- includes robust error handling and input validation with Pydantic

Provide src/sentineldns/service/run.py to start:
python -m sentineldns.service.run --host 127.0.0.1 --port 8787

---

# 7) CLI

Implement src/sentineldns/cli/main.py with commands:

sentineldns download-data
- downloads Tranco + URLhaus (and optional PhishTank if configured)
- writes to data/raw/

sentineldns build-dataset
- normalizes/extracts domains
- writes labeled CSV to data/processed/

sentineldns train-domain-risk
- trains supervised model
- writes artifacts to data/artifacts/domain_risk/
- prints metrics

sentineldns train-anomaly
- builds windowed features from simulation + optional local logs
- trains anomaly model
- writes artifacts

sentineldns simulate
- creates a simulation file with:
  - normal browsing-like domains
  - an injected suspicious segment (DGA-like + beaconing)
- outputs JSONL to data/simulations/sample.jsonl

sentineldns replay --file data/simulations/sample.jsonl
- replays events in real time:
  - scores domains
  - aggregates into windows
  - calls /score/window and prints alerts
- also writes a local SQLite (optional) for demo parity

---

# 8) Simulation Format

Use JSONL where each line is:
{
  "ts": "ISO8601",
  "domain": "abc123-example.com",
  "rcode": "NOERROR|NXDOMAIN",
  "qtype": "A|AAAA"
}

Include a ready-made simulation at:
data/simulations/sample.jsonl

---

# 9) macOS App (SwiftUI) — MVP Wiring

Create a minimal SwiftUI macOS app (apps/macos) that reads either:
- live events from a local simulator file bundled in Resources
- OR (later) real DNS events from a NetworkExtension

For MVP:
- Use the bundled JSONL simulation to populate the UI and trigger alerts.
- For each domain, call the local FastAPI service to get risk scoring.
- Aggregate into 5-minute windows and call /score/window.

Screens:
- DashboardView: status pill + last alert summary + "Run Demo" button
- ActivityView: list recent domains (domain, category, score)
- AlertsView: list alerts (timestamp, label, summary)
- SettingsView: service URL + toggle "Use Simulation"

Networking:
- APIClient.swift should call http://127.0.0.1:8787 by default
- handle service not running with user-friendly error

Important:
- The app must still run if service is down by showing a "Start the service" message.

---

# 10) Notebook Requirements

## 01_domain_risk_train_eval.ipynb
- load data/processed/labeled_domains.csv
- show dataset stats
- train model baseline
- PR curve + confusion matrix
- choose threshold for low FPR
- show top false positives + top true positives
- save artifacts via src/sentineldns/models/export.py

## 02_anomaly_train_eval.ipynb
- generate / load simulations
- compute window features
- train isolation forest
- show detection on injected incident segment
- explain false alerts

---

# 11) Tests

Write tests for:
- domain normalization edge cases
- entropy computation correctness
- API /health and /score/domain returns valid schema
- small smoke test training on tiny sample data

Use pytest.

---

# 12) Build & Run Instructions (README)

README must include:
- prerequisites (Python 3.10+ recommended, macOS)
- create venv, install: pip install -e ".[dev]"
- `make setup`, `make data`, `make train`, `make serve`
- start mac app: open Xcode project and run
- demo steps:
  1) Start service
  2) Click "Run Demo" in app
  3) Observe alert + explanations

Also include:
- limitations (cannot guarantee infection detection)
- privacy statement (local only)
- roadmap (real DNS capture via NetworkExtension; router agent later)

---

# 13) Makefile

Provide targets:
- setup
- data
- dataset
- train
- serve
- simulate
- test
- format (ruff/black)

---

# 14) Packaging

Use pyproject.toml with:
- dependencies: fastapi, uvicorn, pydantic, numpy, pandas, scikit-learn, joblib, tldextract (optional), publicsuffix2 (optional), python-Levenshtein (optional)
- dev deps: pytest, ruff, black

Be careful: keep install simple.

---

# 15) Quality Bar

- Code must be readable, documented, typed where reasonable.
- No placeholder TODOs except in "Nice-to-have" sections.
- All commands should work on a clean machine.
- Provide sensible defaults and clear errors.

Now generate the full repository accordingly.