# SentinelDNS MVP Release Checklist

Use this checklist before creating a release tag.

## 1) Local repo state

- [ ] `git status` is clean on `main`
- [ ] Local `main` is up to date with `origin/main`
- [ ] No accidental large/generated files are staged

## 2) Environment and tests

- [ ] `python3 -m venv .venv`
- [ ] `source .venv/bin/activate`
- [ ] `pip install -e ".[dev]"`
- [ ] `make test` passes

## 3) Data/model pipeline sanity

- [ ] `make data`
- [ ] `make dataset`
- [ ] `make simulate`
- [ ] `make train`
- [ ] Domain/anomaly artifacts exist under `data/artifacts/`

## 4) Service/API demo

- [ ] Start service: `make serve`
- [ ] Health check: `curl http://127.0.0.1:8787/health`
- [ ] Replay check:
  - `sentineldns replay --file data/simulations/sample.jsonl --service-url http://127.0.0.1:8787`
- [ ] Confirm at least one `Unusual` or `Likely Compromise` alert in replay

## 5) Notebook validation

- [ ] `notebooks/01_domain_risk_train_eval.ipynb` executes successfully
- [ ] `notebooks/02_anomaly_train_eval.ipynb` executes successfully
- [ ] PR curve / confusion matrix / anomaly score plot render as expected

## 6) macOS app smoke check

- [ ] Open `apps/macos/Package.swift` in Xcode
- [ ] Run app target
- [ ] Dashboard loads with service up and service down
- [ ] `Run Demo` populates Activity + Alerts views

## 7) Documentation and release

- [ ] README setup/demo steps match current commands
- [ ] Limitations and privacy statements are present
- [ ] Tag release:
  - `git tag -a v0.1.0 -m "SentinelDNS MVP v0.1.0"`
  - `git push origin v0.1.0`
