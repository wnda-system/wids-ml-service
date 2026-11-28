#!/usr/bin/env python3
"""Run the P6 LightGBM WIDS model on a sensor capture file (CSV or CSV.GZ, one row per 802.11 frame).

    python infer.py capture.csv.gz                  -> predictions.csv
    python infer.py capture.csv.gz -o out.csv --threads 2

Steps (same maths as training): sort by time -> per-frame features (features.derive) -> windows of 50 frames,
stride 25 -> RSSI minus the window median -> scale -> mean/std/min/max per feature -> LightGBM.
One file is treated as one capture session. Output has one row per window; no MAC address or SSID is written.
"""
import argparse, json, sys, time, warnings
from pathlib import Path
import numpy as np
import pandas as pd
import lightgbm as lgb
import features as fv

HERE = Path(__file__).resolve().parent
RSSI = "wlan_radio.signal_dbm"
CHUNK = 5000   # windows per batch, keeps memory low on a small machine


class Model:
    def __init__(self, model_dir=HERE / "model", threads=1):
        self.p = json.load(open(Path(model_dir) / "preprocess.json"))
        self.booster = lgb.Booster(model_file=str(Path(model_dir) / "lightgbm_seed1.txt"))
        self.threads = threads
        if self.booster.num_feature() != len(self.p["tab_names"]):
            sys.exit("model and preprocess.json do not match")
        self.cols = [self.p["all_features"].index(f) for f in self.p["features"]]
        self.mean = np.asarray(self.p["mean"], np.float32)
        self.std = np.asarray(self.p["std"], np.float32)
        self.needed = list(dict.fromkeys(self.p["base_features"] + fv.AUX_RAW_COLUMNS + ["frame.len", "radiotap.length"]))

    def tabular(self, windows):
        """(N, 50, all features) unscaled -> (N, 153) model input"""
        # Must be C-contiguous: summation order changes float32 rounding, and the model is sensitive to it
        r = np.ascontiguousarray(windows[:, :, self.cols], dtype=np.float32)
        i = self.p["features"].index(RSSI)
        with np.errstate(invalid="ignore"), warnings.catch_warnings():
            warnings.simplefilter("ignore", RuntimeWarning)          # a window with no RSSI at all stays NaN
            r[:, :, i] -= np.nanmedian(r[:, :, i], axis=1, keepdims=True)
        x = (r - self.mean) / self.std
        nan = np.isnan(x)
        x[~np.isfinite(x)] = 0.0
        parts = [x.mean(1), x.std(1), x.min(1), x.max(1)]
        if self.p["sparse_idx"]:
            parts.append(1.0 - nan.mean(1)[:, self.p["sparse_idx"]])
        return np.concatenate(parts, 1).astype(np.float32)

    def predict(self, raw, app_fix=True):
        """raw: DataFrame of strings, one row per frame -> DataFrame, one row per window"""
        t = pd.to_numeric(raw["frame.time_epoch"], errors="coerce")
        raw = raw[t.notna()].assign(_t=t[t.notna()]).sort_values("_t", kind="stable").reset_index(drop=True)
        T, stride = self.p["T"], self.p["stride"]
        if len(raw) < T:
            sys.exit(f"need at least {T} frames, got {len(raw)}")
        tt = raw["_t"].to_numpy()
        if app_fix:
            with warnings.catch_warnings():                           # pandas deprecation notice inside features.py
                warnings.simplefilter("ignore", FutureWarning)
                raw = fv.app_to_awid3(raw)                            # sensor files only: -1 and RSSI 0 mean "empty"
        X = fv.derive(raw, self.p["base_features"])[self.p["all_features"]].to_numpy(np.float32)
        starts = np.arange(0, len(X) - T + 1, stride)
        P = []
        for s in range(0, len(starts), CHUNK):
            idx = starts[s:s + CHUNK][:, None] + np.arange(T)[None, :]
            P.append(self.booster.predict(self.tabular(X[idx]), num_threads=self.threads))
        P = np.concatenate(P)
        classes = self.p["classes"]
        out = pd.DataFrame({"t_start": tt[starts], "t_end": tt[starts + T - 1], "pred_class": np.array(classes)[P.argmax(1)]})
        for k, c in enumerate(classes):
            out[f"p_{c}"] = P[:, k]
        return out


def read_capture(path, needed):
    raw = pd.read_csv(path, dtype=str, low_memory=False, usecols=lambda c: c in needed)
    must = ["frame.time_epoch", "frame.len", "radiotap.length", "wlan.fc.type", "wlan.fc.subtype"]
    missing = [c for c in must if c not in raw]
    if missing:
        sys.exit(f"input is missing required columns: {missing}")
    absent = [c for c in needed if c not in raw]
    if absent:
        print(f"note: columns not in the input, treated as empty: {absent}", file=sys.stderr)
    return raw


def peak_mb():
    try:
        import resource
        return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024      # Linux reports KB
    except ImportError:
        return float("nan")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("capture")
    ap.add_argument("-o", "--out", default="predictions.csv")
    ap.add_argument("--threads", type=int, default=1)
    ap.add_argument("--no-app-fix", action="store_true", help="input is a plain tshark export, not a sensor file")
    a = ap.parse_args()
    t0 = time.time()
    m = Model(threads=a.threads)
    t1 = time.time()
    raw = read_capture(a.capture, m.needed)
    out = m.predict(raw, app_fix=not a.no_app_fix)
    t2 = time.time()
    out.to_csv(a.out, index=False, float_format="%.6f")
    dur = float(out.t_end.max() - out.t_start.min())
    print(f"frames {len(raw):,} | windows {len(out):,} | capture length {dur:.1f} s")
    print(f"model load {t1 - t0:.2f} s | read + features + predict {t2 - t1:.2f} s "
          f"({len(out) / max(t2 - t1, 1e-9):,.0f} windows/s) | peak memory {peak_mb():.0f} MB")
    print("predicted windows per class:")
    print(out.pred_class.value_counts().to_string())
    print(f"wrote {a.out}")


if __name__ == "__main__":
    main()
