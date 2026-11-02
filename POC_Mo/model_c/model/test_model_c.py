"""Run on the sensor before enabling Model C:  python test_model_c.py

Loads model.joblib + meta.json, recomputes predict_proba for sample_windows.csv
and checks it against expected_proba.csv (computed on the training machine).
"""
import json, os, sys, time

import joblib
import numpy as np
import pandas as pd

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from model_c_features import FEATURE_VERSION, FEATURES, model_features  # noqa: E402

ATOL = 1e-9


def decide(proba, classes, thr):
    """Sensor rule: X if proba[X] >= thr[X] and X != normal; several -> highest proba."""
    out = []
    for row in proba:
        ok = [(p, c) for p, c in zip(row, classes) if c != "normal" and p >= thr[c]]
        out.append(max(ok)[1] if ok else "normal")
    return np.array(out)


def main():
    meta = json.load(open(os.path.join(HERE, "meta.json")))
    model = joblib.load(os.path.join(HERE, "model.joblib"))
    win = pd.read_csv(os.path.join(HERE, "sample_windows.csv"), index_col="win")
    exp = pd.read_csv(os.path.join(HERE, "expected_proba.csv"), index_col="win")

    assert meta["feature_version"] == FEATURE_VERSION == 2
    assert meta["features"] == FEATURES, "meta.json features != model_c_features.FEATURES"
    assert list(model.classes_) == meta["classes"], (list(model.classes_), meta["classes"])
    assert set(meta["thresholds"]) == set(meta["classes"]) - {"normal"}
    assert len(win.columns) == 36, f"sample_windows.csv must hold the 36 windows() columns, has {len(win.columns)}"

    X = model_features(win)
    assert list(X.columns) == FEATURES and X.index.equals(win.index)
    assert np.isfinite(X.to_numpy()).all()

    proba = model.predict_proba(X)
    want = exp[meta["classes"]].to_numpy()
    err = np.abs(proba - want).max()
    assert err <= ATOL, f"predict_proba differs from expected by {err:.3g} (> {ATOL})"

    dec = decide(proba, meta["classes"], meta["thresholds"])
    bad = (dec != exp["decision"].to_numpy()).sum()
    assert bad == 0, f"{bad} decisions differ from expected_proba.csv"

    # speed: ~10 rows every 5 s on the sensor
    t = time.perf_counter()
    for _ in range(20):
        model.predict_proba(model_features(win.iloc[:10]))
    per_call = (time.perf_counter() - t) / 20

    print(f"OK: {len(win)} windows, max |proba diff| {err:.2e}, decisions identical, "
          f"{per_call * 1000:.1f} ms per 10-row call")
    print(pd.crosstab(exp["label"], pd.Series(dec, index=exp.index, name="decision")).to_string())


if __name__ == "__main__":
    main()
