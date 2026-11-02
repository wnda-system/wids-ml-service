# POC_Mo — Model C proof of concept (Mo)

A first end-to-end inference service, built and run during the proof-of-concept
phase (Oct 2026) before this repository's FastAPI service. **Model C**
(`awid3-mac-v1`) is a HistGradientBoosting classifier trained on AWID3 that
labels each one-second window of the sensor's features as `normal` or one of 8
attack classes. The sensor called it in *shadow mode* (predictions logged, no
alerts) for 4 days; the results are in the edge repository
(`POC_Mo/mo_app/model_c_shadow_report.md`).

Useful here as a reference for the real service: the API contract, the golden
test runner, and what a model package looks like.

| Path | What it is |
|---|---|
| `model_c/service/model_c_service.py` | HTTP service (standard library): `GET /v1/info`, `POST /v1/predict`, `GET /v1/health`; Bearer token; 401 / 409 (feature version) / 413 |
| `model_c/service/check_service.py` | Contract checks + golden test vectors (23 checks); `--record` rewrites the expected responses |
| `model_c/test_vectors/` | Golden requests/responses: AWID3 deauth and evil twin, our normal traffic, a gap in the data |
| `model_c/model/meta.json` | Package metadata: feature list, classes, per-class thresholds, metrics, library versions |
| `model_c/model/model_c_features.py` | The model's 14 features, computed from the sensor's 36 per-second features |
| `model_c/model/test_model_c.py` + `sample_windows.csv` + `expected_proba.csv` | Package self-test: recompute probabilities and compare to the training machine |
| `model_c/report.md` | Training report: data split, per-class recall, false alarms on our traffic, feature importance |
| `model_c/docs/` | Training plan v2 (API contract in section 6), AWID3 structure notes, AWID3 vs our feature distributions |

## Not included

- **`model.joblib` (6.7 MB)** — the trained model. Kept on the sensor
  (`~/model_c/model/`) and the training machine; to be stored in the `models`
  bucket (or a release) rather than in git. `test_model_c.py` and the service
  need it next to `meta.json`.
- **`model_c.token`** — the service's bearer token. Never commit it.
- The training machine's address has been replaced with `<hpc-host>`.

## Lessons for the WNDA models

- Trained on AWID3 only, three classes fired constantly on our campus traffic
  (Krack, Evil_Twin, SSDP) and had to be switched off with a threshold above 1.
  Plan per-class enable switches and measure false alarms on our own normal
  traffic before any class may raise alerts.
- `feature_version` is checked on every request (409 on mismatch): the sensor
  and the model must agree on how features are computed.
