# SentinelDNS MVP

SentinelDNS is a local-first macOS DNS monitoring MVP. It scores queried domains for phishing/malware risk, detects unusual DNS behavior in time windows, and explains alerts in plain English.

## What is included

- Python data/training pipeline:
  - benign domains from Tranco
  - malicious domains from URLhaus (optional PhishTank)
- Supervised domain risk model (`LogisticRegression`)
- Unsupervised anomaly detector (`IsolationForest`) on DNS window stats
- Local FastAPI inference service with `/score/domain` and `/score/window`
- SwiftUI macOS app skeleton wired to local service and simulation data
- Simulation and replay mode for guaranteed demo alerts
- Evaluation notebooks for model training/evaluation analysis
- Pytest coverage for normalization, entropy correctness, API smoke

## Privacy

All processing runs locally on your Mac. No cloud service is required.

## Limitations

- This tool cannot guarantee infection detection.
- Domain-only features do not inspect payloads or process-level behavior.
- Feeds can contain stale or noisy indicators.
- False positives and false negatives are expected in MVP form.

## Roadmap

- Real DNS capture with NetworkExtension DNS proxy
- Optional local domain blocking pipeline
- Router/edge collector agent for household-level visibility

## Prerequisites

- macOS
- Python 3.10+
- Xcode 15+ (for macOS app)

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
make setup
```

## Build dataset and train models

```bash
make data
make dataset
make simulate
make train
```

## Run the local inference service

```bash
make serve
```

Service runs by default at `http://127.0.0.1:8787`.

## Run simulation replay from CLI

```bash
sentineldns replay --file data/simulations/sample.jsonl --service-url http://127.0.0.1:8787
```

## Run tests

```bash
make test
```

## Format code

```bash
make format
```

## macOS app (SwiftUI)

1. In Finder or terminal, open `apps/macos/Package.swift` with Xcode.
2. Run the `SentinelDNS` target.
3. Confirm service is running (`make serve`).
4. Click **Run Demo** in the Dashboard view.

The app handles service downtime gracefully and will show a "Start the service" message if unreachable.

## Demo steps

1. Start service: `make serve`
2. In app, click **Run Demo**
3. Observe status transition and alert explanations

## CLI commands

- `sentineldns download-data`
- `sentineldns build-dataset`
- `sentineldns train-domain-risk`
- `sentineldns train-anomaly`
- `sentineldns simulate`
- `sentineldns replay --file data/simulations/sample.jsonl`

## Notes on feed sourcing

- Tranco latest list is downloaded from Tranco public endpoints.
- If Tranco download fails, pass `--tranco-local /path/to/tranco.csv`.
- URLhaus feed is downloaded from abuse.ch.
- PhishTank integration is optional via `--enable-phishtank` and `PHISHTANK_URL`.
