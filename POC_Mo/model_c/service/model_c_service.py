"""Model C HTTP service — API contract: model_c_training_plan_v2.md section 6.

    python model_c_service.py [--host 0.0.0.0] [--port 8500] [--model-dir ../model]
                              [--token-file model_c.token] [--threads 2]

Stateless: every request carries all the windows it needs. Standard library
HTTP server only; the model runs one request at a time.
"""
import argparse, hmac, json, logging, math, os, sys, threading, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))

FEATURE_VERSION = 2
CONTEXT_SECONDS = 10      # longest look-back among the model's inputs (deauth_to_one_client_10s)
MAX_BODY = 4 << 20        # bytes
MAX_SPAN = 3600           # seconds covered by one request (after gap filling)
# the 36 columns of features.windows() at FEATURE_VERSION 2
WIN_COLS = ["frames", "mgmt", "ctrl", "data", "beacon", "probe_req", "auth", "assoc_req", "deauth", "disassoc",
            "rts", "cts", "retry_ratio", "protected_ratio", "signal_mean", "signal_std", "len_mean", "n_ssid",
            "n_bssid", "n_sa", "n_dest_mac", "arp", "dhcp", "mdns", "ssdp", "tcp", "arp_reply_ratio",
            "max_bssid_per_ssid", "new_bssid_known_ssid", "deauth_seq_out_of_order", "tsf_offset_switches",
            "bssid_signal_range", "bssid_beacon_rate", "deauth_to_one_client_10s", "arp_ip_mac_flips_10s",
            "arp_ips_per_mac_60s"]

log = logging.getLogger("model_c")


class ApiError(Exception):
    def __init__(self, status, message):
        super().__init__(message)
        self.status, self.message = status, message


class Model:
    def __init__(self, model_dir, threads):
        import joblib
        import numpy as np
        import pandas as pd
        from threadpoolctl import threadpool_limits

        sys.path.insert(0, model_dir)
        from model_c_features import FEATURES, model_features

        self.np, self.pd = np, pd
        self.meta = json.load(open(os.path.join(model_dir, "meta.json")))
        self.model = joblib.load(os.path.join(model_dir, "model.joblib"))
        self.classes = [str(c) for c in self.model.classes_]
        if self.classes != self.meta["classes"] or FEATURES != self.meta["features"]:
            raise SystemExit("model.joblib / model_c_features.py do not match meta.json")
        if self.meta["feature_version"] != FEATURE_VERSION:
            raise SystemExit(f"meta.json feature_version {self.meta['feature_version']} != {FEATURE_VERSION}")
        self.thresholds = self.meta["thresholds"]
        self.model_features = model_features
        self.limit = lambda: threadpool_limits(threads)
        self.lock = threading.Lock()
        self.info = {
            "model": self.meta["name"],
            "feature_version": FEATURE_VERSION,
            "context_seconds": CONTEXT_SECONDS,
            "classes": self.classes,
            "thresholds": self.thresholds,
            "class_to_alert_type": self.meta["class_to_alert_type"],
        }

    def predict(self, req):
        np, pd = self.np, self.pd
        if not isinstance(req, dict):
            raise ApiError(400, "body must be a JSON object")
        if req.get("feature_version") != FEATURE_VERSION:
            raise ApiError(409, f"feature_version must be {FEATURE_VERSION}, got {req.get('feature_version')!r}")
        wins, pf = req.get("windows"), req.get("predict_from")
        if not isinstance(wins, list) or not wins:
            raise ApiError(400, "windows must be a non-empty list")
        if not _is_int(pf):
            raise ApiError(400, "predict_from must be an integer")

        rows, idx = [], []
        for i, w in enumerate(wins):
            if not isinstance(w, dict) or not _is_int(w.get("win")) or not isinstance(w.get("features"), dict):
                raise ApiError(400, f"windows[{i}] must be {{\"win\": int, \"features\": {{...}}}}")
            f = w["features"]
            missing = [c for c in WIN_COLS if c not in f]
            if missing:
                raise ApiError(400, f"windows[{i}] missing features: {missing}")
            vals = []
            for c in WIN_COLS:
                v = f[c]
                if isinstance(v, bool) or not isinstance(v, (int, float)):
                    raise ApiError(400, f"windows[{i}].features.{c} must be a number")
                vals.append(float(v))
            rows.append(vals)
            idx.append(int(w["win"]))
        if len(set(idx)) != len(idx):
            raise ApiError(400, "duplicate win values")
        lo, hi = min(idx), max(idx)
        if hi - lo + 1 > MAX_SPAN:
            raise ApiError(413, f"windows span {hi - lo + 1} s > {MAX_SPAN} s")

        df = pd.DataFrame(rows, index=idx, columns=WIN_COLS).sort_index()
        df = df.reindex(range(lo, hi + 1), fill_value=0.0)   # missing seconds -> 0 (contract)
        df.index.name = "win"
        df = df[df.index >= pf]
        if df.empty:
            return {"model": self.meta["name"], "results": []}

        X = self.model_features(df)
        with self.lock, self.limit():
            proba = self.model.predict_proba(X)
        results = []
        for win, p in zip(df.index, proba):
            passing = [(p[k], c) for k, c in enumerate(self.classes)
                       if c != "normal" and p[k] >= self.thresholds[c]]
            predicted = max(passing)[1] if passing else "normal"
            results.append({"win": int(win),
                            "proba": {c: float(p[k]) for k, c in enumerate(self.classes)},
                            "predicted": predicted, "alert": bool(passing)})
        return {"model": self.meta["name"], "results": results}


def _is_int(v):
    return isinstance(v, int) and not isinstance(v, bool) or (isinstance(v, float) and v.is_integer() and math.isfinite(v))


def make_handler(model, token):
    expected = ("Bearer " + token).encode()

    class Handler(BaseHTTPRequestHandler):
        server_version = "model-c/1"
        sys_version = ""

        def log_message(self, fmt, *args):  # replaced by _log; never logs headers
            pass

        def _send(self, status, body):
            data = json.dumps(body, allow_nan=False).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            if status == 401:
                self.send_header("WWW-Authenticate", "Bearer")
            self.end_headers()
            self.wfile.write(data)
            return status

        def _authorized(self):
            got = (self.headers.get("Authorization") or "").encode()
            return hmac.compare_digest(got, expected)

        def _handle(self, method):
            t0 = time.perf_counter()
            extra = ""
            try:
                if not self._authorized():
                    status = self._send(401, {"error": "missing or invalid bearer token"})
                elif method == "GET" and self.path == "/v1/health":
                    status = self._send(200, {"ok": True, "model": model.meta["name"]})
                elif method == "GET" and self.path == "/v1/info":
                    status = self._send(200, model.info)
                elif method == "POST" and self.path == "/v1/predict":
                    n = int(self.headers.get("Content-Length") or 0)
                    if n > MAX_BODY:
                        raise ApiError(413, f"body larger than {MAX_BODY} bytes")
                    try:
                        req = json.loads(self.rfile.read(n))
                    except (ValueError, UnicodeDecodeError):
                        raise ApiError(400, "body is not valid JSON")
                    out = model.predict(req)
                    extra = (f" sensor={str(req.get('sensor_id'))[:64]!r} windows={len(req['windows'])}"
                             f" results={len(out['results'])} alerts={sum(r['alert'] for r in out['results'])}")
                    status = self._send(200, out)
                elif self.path in ("/v1/health", "/v1/info", "/v1/predict"):
                    status = self._send(405, {"error": f"{method} not allowed on {self.path}"})
                else:
                    status = self._send(404, {"error": "not found"})
            except ApiError as e:
                status = self._send(e.status, {"error": e.message})
            except Exception:
                log.exception("internal error")
                status = self._send(500, {"error": "internal error"})
            log.info("%s %s %s %d %.1fms%s", self.client_address[0], method, self.path, status,
                     (time.perf_counter() - t0) * 1000, extra)

        def do_GET(self):
            self._handle("GET")

        def do_POST(self):
            self._handle("POST")

    return Handler


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=8500)
    ap.add_argument("--model-dir", default=os.path.join(HERE, "..", "model"))
    ap.add_argument("--token-file", default=os.path.join(HERE, "model_c.token"))
    ap.add_argument("--threads", type=int, default=2)
    a = ap.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    st = os.stat(a.token_file)
    if st.st_mode & 0o077:
        raise SystemExit(f"{a.token_file} must be chmod 600 (is {oct(st.st_mode & 0o777)})")
    token = open(a.token_file).read().strip()
    if len(token) < 32:
        raise SystemExit("token must be at least 32 characters")

    model = Model(os.path.abspath(a.model_dir), a.threads)
    srv = ThreadingHTTPServer((a.host, a.port), make_handler(model, token))
    log.info("model %s listening on %s:%d (threads=%d)", model.meta["name"], a.host, a.port, a.threads)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
