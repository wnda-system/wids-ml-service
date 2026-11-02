"""Check a running Model C service against the API contract and the test vectors.

    python check_service.py --url http://127.0.0.1:8500 [--record] [--token-file model_c.token]

--record  writes test_vectors/response_*.json from the service's answers
(default)  compares the service's answers with the stored response_*.json
The token is read from the file and never printed.
"""
import argparse, glob, json, os, sys, time
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
VECTORS = os.path.join(HERE, "..", "test_vectors")
ATOL = 1e-12


def call(url, path, token=None, body=None, method=None):
    data = None if body is None else (body if isinstance(body, bytes) else json.dumps(body).encode())
    req = urllib.request.Request(url + path, data=data, method=method or ("POST" if data else "GET"))
    if token is not None:
        req.add_header("Authorization", "Bearer " + token)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    t = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            status, out = r.status, r.read()
    except urllib.error.HTTPError as e:
        status, out = e.code, e.read()
    return status, json.loads(out or b"null"), (time.perf_counter() - t) * 1000


def same(a, b):
    if a["model"] != b["model"] or len(a["results"]) != len(b["results"]):
        return False
    for x, y in zip(a["results"], b["results"]):
        if (x["win"], x["predicted"], x["alert"]) != (y["win"], y["predicted"], y["alert"]):
            return False
        if x["proba"].keys() != y["proba"].keys() or any(abs(x["proba"][k] - y["proba"][k]) > ATOL for k in x["proba"]):
            return False
    return True


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", required=True)
    ap.add_argument("--token-file", default=os.path.join(HERE, "model_c.token"))
    ap.add_argument("--record", action="store_true")
    a = ap.parse_args()
    url = a.url.rstrip("/")
    token = open(a.token_file).read().strip()
    fails = []

    def check(name, ok, detail=""):
        print(f"{'PASS' if ok else 'FAIL'}  {name}{('  ' + detail) if detail else ''}")
        if not ok:
            fails.append(name)

    # --- contract / auth
    s, body, ms = call(url, "/v1/health", token)
    check("health 200", s == 200 and body.get("ok") is True, f"{body} {ms:.0f} ms")
    s, info, _ = call(url, "/v1/info", token)
    check("info 200 + fields", s == 200 and set(info) == {"model", "feature_version", "context_seconds", "classes",
                                                           "thresholds", "class_to_alert_type"},
          f"feature_version={info.get('feature_version')} context_seconds={info.get('context_seconds')}")
    for path, method in (("/v1/health", "GET"), ("/v1/info", "GET"), ("/v1/predict", "POST")):
        body = {} if method == "POST" else None
        check(f"{path} no token -> 401", call(url, path, None, body, method)[0] == 401)
        check(f"{path} wrong token -> 401", call(url, path, "x" * len(token), body, method)[0] == 401)

    req = json.load(open(sorted(glob.glob(os.path.join(VECTORS, "request_*.json")))[0]))
    s, body, _ = call(url, "/v1/predict", token, dict(req, feature_version=1))
    check("feature_version 1 -> 409", s == 409, str(body))
    bad = json.loads(json.dumps(req))
    del bad["windows"][0]["features"]["deauth"]
    check("missing feature -> 400", call(url, "/v1/predict", token, bad)[0] == 400)
    check("invalid JSON -> 400", call(url, "/v1/predict", token, b"{not json")[0] == 400)
    check("unknown path -> 404", call(url, "/v2/x", token)[0] == 404)
    check("GET /v1/predict -> 405", call(url, "/v1/predict", token)[0] == 405)
    late = dict(req, predict_from=req["windows"][-1]["win"] + 1)
    s, body, _ = call(url, "/v1/predict", token, late)
    check("predict_from after last win -> empty results", s == 200 and body["results"] == [])

    # --- test vectors
    for p in sorted(glob.glob(os.path.join(VECTORS, "request_*.json"))):
        name = os.path.basename(p)[len("request_"):-len(".json")]
        req = json.load(open(p))
        s, out, ms = call(url, "/v1/predict", token, req)
        wins = [w["win"] for w in req["windows"]]
        want_wins = [w for w in range(min(wins), max(wins) + 1) if w >= req["predict_from"]]
        got_wins = [r["win"] for r in out.get("results", [])]
        check(f"{name}: 200 + one result per second >= predict_from (gaps filled)",
              s == 200 and got_wins == want_wins, f"{len(got_wins)} results, {ms:.0f} ms")
        summary = [(r["win"], r["predicted"], r["alert"]) for r in out.get("results", [])]
        print("      ", summary)
        rp = os.path.join(VECTORS, f"response_{name}.json")
        if a.record:
            json.dump(out, open(rp, "w"), indent=1)
        else:
            check(f"{name}: same as {os.path.basename(rp)}", same(out, json.load(open(rp))))

    # --- latency for a ~70 s request (contract: < 1 s)
    big = json.load(open(os.path.join(VECTORS, "request_gap_ours.json")))
    w0 = big["windows"]
    big["windows"] = [dict(w, win=w0[0]["win"] + i) for i, w in enumerate((w0 * 4)[:70])]
    big["predict_from"] = big["windows"][-5]["win"]
    times = sorted(call(url, "/v1/predict", token, big)[2] for _ in range(20))
    check("70-window request < 1 s", times[-1] < 1000,
          f"median {times[10]:.0f} ms, max {times[-1]:.0f} ms over 20 calls")

    print("\nALL PASS" if not fails else f"\n{len(fails)} FAILED: {fails}")
    sys.exit(1 if fails else 0)


if __name__ == "__main__":
    main()
