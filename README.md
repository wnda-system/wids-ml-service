# wids-ml-service

Model inference service for [WNDA System](https://github.com/wnda-system). It hosts the attack detection (WIDS) model and the network performance anomaly model behind a small HTTP API.

> 🚧 **Status:** project scaffolding in progress.

## Stack

Python, FastAPI, PyTorch, scikit-learn / XGBoost / LightGBM.

## Design

- **Stateless.** Every request carries the full sequence of feature windows a model needs. The service keeps no memory between calls, so it can restart at any time and replaying the same input always gives the same output.
- **Model packages are swappable.** Each model is loaded from a versioned package. Replacing a model does not require code changes.
- **Every response names the model version** that produced it, so the backend can trace each prediction.

## API

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/predict/wids` | Classify a sequence of feature windows as normal or one of the attack classes |
| `POST` | `/predict/performance` | Score feature windows for performance anomalies |
| `GET` | `/model-info` | Names, versions and thresholds of the loaded models |
| `GET` | `/health` | Liveness check |

The contract lives in `api/openapi.yaml`. Errors follow [RFC 9457](https://www.rfc-editor.org/rfc/rfc9457) Problem Details.

## Model package format

```
models/<name>/<version>/
  model.*               trained weights (ONNX or PyTorch)
  feature_spec.json     feature names, order, schema version, sequence length
  scaler.*              preprocessing parameters
  labels.json           class index → label
  thresholds.json       decision and reject thresholds
  golden/               sample inputs with expected outputs
```

The service runs the golden samples at startup and refuses to start if the outputs do not match.

## Getting started

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

## Contributing

- Branch from `dev`, open a pull request back to `dev`. `main` receives releases only.
- Pull request titles follow [Conventional Commits](https://www.conventionalcommits.org/). Pull requests are squash-merged.
- Model weights are not stored in git.

## Team

- Naran Wongvuttisaroj
- Boonyapon Boontub
