"""
features.py -- (v2 + context features + feature sets F1-F4) code that turns raw rows from tshark/AWID3 CSV into model-ready features.
Shared by (1) AWID3 cleaning on the HPC and (2) the extractor on the mini PC  => exactly the same logic.
Do not copy these functions elsewhere; always import them (Rules of ML #32).
"""
from __future__ import annotations
import numpy as np
import pandas as pd

# ---------------- Label (v2) ----------------
# scope "mac": keep only 802.11-level attacks (7 types) + Normal
LABEL_MAP_MAC = {"Normal": 0, "Deauth": 1, "Disas": 2, "(Re)Assoc": 3, "RogueAP": 4,
                 "Krack": 5, "Kr00k": 6, "Evil_Twin": 7}
# Application-level attacks -- the payload is encrypted, so the mini PC cannot see it
APP_LAYER_ATTACKS = {"SSH", "Botnet", "Malware", "SQL_Injection", "SSDP", "Website_spoofing"}
# Typos confirmed by the v1 inventory scan (SDDP 43,456 rows, Kr00K 5,630 rows) -- do not add entries without a confirming scan
LABEL_TYPO_FIX = {"SDDP": "SSDP", "Kr00K": "Kr00k"}
IGNORE = -1        # rows that are not training samples (app-layer attack / empty label) but must stay in the time order


def normalize_label(x) -> str:
    # Strip whitespace, treat None/NaN as empty and fix known label typos.
    x = "" if x is None or (isinstance(x, float) and x != x) else str(x).strip()
    return LABEL_TYPO_FIX.get(x, x)


def build_label_map(scope: str) -> dict[str, int]:
    # Label name -> class id for the chosen scope.
    if scope == "mac":
        return dict(LABEL_MAP_MAC)
    if scope == "mac_plus_other":                  # ablation: merge app-layer attacks into a single class
        m = dict(LABEL_MAP_MAC); m["Other_attack"] = len(m); return m
    raise ValueError(scope)


def map_labels(raw: pd.Series, scope: str) -> pd.Series:
    """Return label_id (int16). Rows that are not training samples (app-layer in scope mac, empty label) = IGNORE (-1).
    Rows are not removed because the time order must be preserved (avoids fake windows spanning a gap). Unknown name -> raise (fail loud)."""
    lm = build_label_map(scope)
    lower = {k.lower(): v for k, v in lm.items()}
    app_lower = {a.lower() for a in APP_LAYER_ATTACKS}
    cache = {}  # raw label -> class id, computed once per unique value
    for x in raw.unique():
        n = normalize_label(x)
        if n == "":
            cache[x] = IGNORE
        elif n in lm:
            cache[x] = lm[n]
        elif n.lower() in lower:
            cache[x] = lower[n.lower()]
        elif n.lower() in app_lower:
            cache[x] = lm["Other_attack"] if scope == "mac_plus_other" else IGNORE
        else:
            raise ValueError(f"Unknown label {x!r}")
    return raw.map(cache).astype("int16")


# ---------------- Convert raw values to numbers ----------------
def to_numeric(s: pd.Series) -> pd.Series:
    """Supports: '12', '-55', '0x00000002', 'True'/'False', multi-valued '-55,-57' (first value is used)."""
    if pd.api.types.is_numeric_dtype(s):
        return s.astype("float64")
    t = s.astype("string").str.split(",", n=1).str[0].str.strip()
    t = t.replace({"True": "1", "False": "0", "true": "1", "false": "0", "": pd.NA})
    out = pd.to_numeric(t, errors="coerce")
    hexmask = t.str.startswith("0x", na=False)
    if hexmask.any():
        out[hexmask] = t[hexmask].map(lambda v: int(v, 16)).astype("float64")
    return out.astype("float64")


RSSI_COLS = ("wlan_radio.signal_dbm", "radiotap.dbm_antsignal")


def app_to_awid3(df: pd.DataFrame) -> pd.DataFrame:
    """Mini PC app data -> same semantics as AWID3 (use on app data only, never on AWID3).
      1) Older app versions use -1 for empty values -> NaN (newer files already write blanks; this is safe for both; use validate_field.py to check that new files have no -1 left)
      2) RSSI == 0 is a value the driver fills in itself (Mo reported 28 QoS-data rows) and is unreliable -> NaN (AWID3's 30.6M frames contain no RSSI == 0, so training is unaffected)"""
    out = df.replace({-1: np.nan, "-1": np.nan, -1.0: np.nan})
    for c in RSSI_COLS:
        if c in out:
            v = pd.to_numeric(out[c], errors="coerce")
            out[c] = out[c].mask(v == 0, np.nan)
    return out


# ---------------- Derived (behavioural) features ----------------
# Every one is computed only from fields the mini PC can really capture
DERIVED = ["frames_per_sec", "deauth_disas_per_sec", "unique_tx_per_sec", "eapol_per_sec",
           "seq_gap_tx", "rssi_delta_tx", "eapol_replay_repeat"]
INDICATORS = ["has_eapol", "has_reason_code", "has_rsn_info", "has_seq"]
# ---- v3 context features (P1.2) ----
L = 5.0   # seconds: how far back to look within the same session/buffer (set in one place). The first 5 seconds of every session/buffer are under-counted (buffer-boundary rule)
CONTEXT = ["tsf_jump_bssid", "n_bssid_per_ssid", "deauth_before_assoc", "prot_data_after_disas", "eapol_m3_repeat"]
TSF_JUMP_CLIP = 1e3
# In many AWID3 files frame.time_epoch is rounded to whole seconds -> dEpoch between adjacent frames = 0 is unusable.
# So compare against the latest adv frame of the same BSSID that is at least TSF_MIN_BASELINE seconds older (time error <=1s/3s), the same rule for every file.
TSF_MIN_BASELINE = 3.0
MAC_LEN = "mac_len"   # frame.len - radiotap.length (frame.len includes the radiotap header, whose length differs between AWID3=56 and the app=38)


def derive(raw: pd.DataFrame, base_features: list[str]) -> pd.DataFrame:
    """
    raw: DataFrame of one session (one AWID3 file or one buffer on the mini PC), already sorted by time.
         Must contain the columns base_features + frame.time_epoch, wlan.seq, wlan.ta/wlan.sa,
         eapol.keydes.replay_counter (if available)
    Returns the final feature DataFrame (float32) in feature_order() order
    """
    # Base features: numeric copy of each raw column (NaN when the column is absent)
    df = pd.DataFrame(index=raw.index)
    for c in base_features:
        df[c] = to_numeric(raw[c]) if c in raw else np.nan

    # (S5) frame length without the radiotap header -- ACK = 14 in both AWID3 and the app
    df[MAC_LEN] = to_numeric(raw["frame.len"]) - to_numeric(raw["radiotap.length"])
    # (S6) protected=1 frames: the mini PC cannot read the body (reason_code) but Wireshark/AWID3 decrypts it -> blank it so both sides match
    if "wlan.fixed.reason_code" in df and "wlan.fc.protected" in raw:
        prot = to_numeric(raw["wlan.fc.protected"]) == 1
        df.loc[prot, "wlan.fixed.reason_code"] = np.nan

    # Per-second aggregates: frame rate, deauth/disassoc rate, distinct transmitters, EAPOL rate
    t = to_numeric(raw["frame.time_epoch"])
    sec = np.floor(t)
    tx = raw.get("wlan.ta", pd.Series(pd.NA, index=raw.index)).astype("string")
    if "wlan.sa" in raw:
        tx = tx.fillna(raw["wlan.sa"].astype("string"))
    ftype = to_numeric(raw["wlan.fc.type"]) if "wlan.fc.type" in raw else pd.Series(np.nan, index=raw.index)
    fsub = to_numeric(raw["wlan.fc.subtype"]) if "wlan.fc.subtype" in raw else pd.Series(np.nan, index=raw.index)
    is_eapol = raw["eapol.type"].notna() & (raw["eapol.type"].astype("string") != "") if "eapol.type" in raw \
        else pd.Series(False, index=raw.index)

    g = pd.DataFrame({"sec": sec, "tx": tx,
                      "deauth": ((ftype == 0) & fsub.isin([10, 12])).astype(int),
                      "eapol": is_eapol.astype(int)})
    by_sec = g.groupby("sec", dropna=False)
    df["frames_per_sec"] = by_sec["sec"].transform("size")
    df["deauth_disas_per_sec"] = by_sec["deauth"].transform("sum")
    df["unique_tx_per_sec"] = by_sec["tx"].transform("nunique")
    df["eapol_per_sec"] = by_sec["eapol"].transform("sum")

    # Sequence-number gap per transmitter
    seq = to_numeric(raw["wlan.seq"]) if "wlan.seq" in raw else pd.Series(np.nan, index=raw.index)
    prev_seq = seq.groupby(tx, dropna=True).shift(1)
    df["seq_gap_tx"] = (seq - prev_seq) % 4096          # normally ~1; spoofed frames jump unusually

    # RSSI change versus the previous frame of the same transmitter
    rssi_col = "wlan_radio.signal_dbm" if "wlan_radio.signal_dbm" in base_features else None   # radiotap.dbm_antsignal is not used (see feature_contract)
    if rssi_col:
        r = df[rssi_col]
        df["rssi_delta_tx"] = r - r.groupby(tx, dropna=True).shift(1)
    else:
        df["rssi_delta_tx"] = np.nan

    # EAPOL replay: same replay counter as the previous EAPOL frame of this transmitter
    if "eapol.keydes.replay_counter" in raw:
        rc = to_numeric(raw["eapol.keydes.replay_counter"]).where(is_eapol)
        prev_rc = rc.groupby(tx, dropna=True).shift(1)
        df["eapol_replay_repeat"] = np.where(is_eapol, (rc == prev_rc).astype(float), np.nan)
    else:
        df["eapol_replay_repeat"] = np.nan

    # Context features (look back L seconds), then indicator flags
    _context_features(df, raw, t, tx, ftype, fsub, is_eapol)
    df["has_eapol"] = is_eapol.astype(float)
    df["has_reason_code"] = df["wlan.fixed.reason_code"].notna().astype(float) if "wlan.fixed.reason_code" in df else 0.0
    df["has_rsn_info"] = df["wlan.rsn.capabilities.mfpc"].notna().astype(float) if "wlan.rsn.capabilities.mfpc" in df else 0.0
    df["has_seq"] = seq.notna().astype(float)
    return df[feature_order(base_features)].astype("float32")


# ---------------- v3 context features ----------------
def _count_prior(ev_key, ev_t, q_key, q_t, inclusive=False):
    """Count events (same key) falling in [q_t - L, q_t) (inclusive=True -> [q_t - L, q_t]).
    ev_key/q_key: string Series (NA = no key -> result NaN). Returns a float ndarray (NaN where q_key is NA)."""
    out = np.full(len(q_key), np.nan)
    ek = pd.Series(np.asarray(ev_key, dtype=object)); et = np.asarray(ev_t, dtype="float64")
    ok = ek.notna().to_numpy() & np.isfinite(et)
    ev = {k: np.sort(et[g.index.to_numpy()]) for k, g in ek[ok].groupby(ek[ok])}
    qk = pd.Series(np.asarray(q_key, dtype=object)); qt = np.asarray(q_t, dtype="float64")
    qok = qk.notna().to_numpy() & np.isfinite(qt)
    side = "right" if inclusive else "left"
    for k, g in qk[qok].groupby(qk[qok]):
        idx = g.index.to_numpy()
        arr = ev.get(k)
        if arr is None:
            out[idx] = 0
        else:
            out[idx] = np.searchsorted(arr, qt[idx], side) - np.searchsorted(arr, qt[idx] - L, "left")
    return out


def _s(raw, col, n_index):
    # String column with empty strings turned into NA; all-NA if the column is absent.
    return raw[col].astype("string").replace("", pd.NA) if col in raw else pd.Series(pd.NA, index=n_index, dtype="string")


def _context_features(df, raw, t, tx, ftype, fsub, is_eapol):
    """Fill the 5 CONTEXT features into df (in place). Looks back L seconds *only within this session/buffer*."""
    idx = raw.index
    tt = t.to_numpy("float64")
    mgmt = (ftype == 0).to_numpy()
    sub = fsub.to_numpy("float64")
    bssid = _s(raw, "wlan.bssid", idx); ssid = _s(raw, "wlan.ssid", idx); ra = _s(raw, "wlan.ra", idx)
    adv = mgmt & np.isin(sub, [5, 8])                        # probe response / beacon

    # (1) tsf_jump_bssid: |dTSF - dEpoch| / max(dEpoch,1), compared with the previous adv frame of the same BSSID
    tsf = to_numeric(raw["wlan.fixed.timestamp"]) if "wlan.fixed.timestamp" in raw else pd.Series(np.nan, index=idx)
    m = adv & bssid.notna().to_numpy() & tsf.notna().to_numpy()
    df["tsf_jump_bssid"] = np.nan
    col = df.columns.get_loc("tsf_jump_bssid")
    if m.any():
        a = pd.DataFrame({"b": bssid.to_numpy()[m], "tsf": tsf.to_numpy()[m], "t": tt[m]}, index=np.where(m)[0])
        for _, g in a.groupby("b"):
            gt, gs = g["t"].to_numpy(), g["tsf"].to_numpy()
            j = np.searchsorted(gt, gt - TSF_MIN_BASELINE, "right") - 1       # latest frame that is at least a baseline older
            ok = j >= 0
            d_ep = (gt[ok] - gt[j[ok]]) * 1e6
            val = np.minimum(np.abs((gs[ok] - gs[j[ok]]) - d_ep) / np.maximum(d_ep, 1.0), TSF_JUMP_CLIP)
            df.iloc[g.index.to_numpy()[ok], col] = val

    # (2) n_bssid_per_ssid: number of BSSIDs advertising the same SSID in the last L seconds (including this frame). Empty/hidden SSID -> NaN
    df["n_bssid_per_ssid"] = np.nan
    m = adv & ssid.notna().to_numpy() & bssid.notna().to_numpy()
    if m.any():
        a = pd.DataFrame({"ssid": ssid.to_numpy()[m], "b": bssid.to_numpy()[m], "t": tt[m]}, index=np.where(m)[0])
        for _, g in a.groupby("ssid"):
            qt = g["t"].to_numpy(); cnt = np.zeros(len(g))
            for _, gb in g.groupby("b"):
                arr = np.sort(gb["t"].to_numpy())
                cnt += (np.searchsorted(arr, qt, "right") - np.searchsorted(arr, qt - L, "left")) > 0
            df.iloc[g.index.to_numpy(), df.columns.get_loc("n_bssid_per_ssid")] = cnt

    # (3) deauth_before_assoc: deauth(12)+disassoc(10) sent TO the same station (RA) in the previous L seconds
    #     The station of an assoc/reassoc request = TA(/SA); of a response = RA.  (RA is used instead of DA: on the mini PC DA==RA always)
    isdd = mgmt & np.isin(sub, [10, 12])
    is_req = mgmt & np.isin(sub, [0, 2]); is_resp = mgmt & np.isin(sub, [1, 3])
    stn = pd.Series(pd.NA, index=idx, dtype="object")
    stn[is_req] = tx[is_req].astype(object); stn[is_resp] = ra[is_resp].astype(object)
    cnt = _count_prior(ra.to_numpy(object)[isdd], tt[isdd], stn.to_numpy(object), tt)
    df["deauth_before_assoc"] = np.where(is_req | is_resp, cnt, np.nan)

    # (4) prot_data_after_disas: protected data frame (protected=1) of a station that sent or received a disassoc(10) in the previous L seconds
    #     The station of a data frame: to-DS (ds=1) -> TA ; from-DS (ds=2) -> RA ; otherwise -> TA
    prot = (to_numeric(raw["wlan.fc.protected"]) == 1).to_numpy() if "wlan.fc.protected" in raw else np.zeros(len(raw), bool)
    ds = to_numeric(raw["wlan.fc.ds"]).to_numpy() if "wlan.fc.ds" in raw else np.full(len(raw), np.nan)
    isdata = (ftype == 2).to_numpy() & prot
    dstn = pd.Series(np.where(ds == 2, ra.astype(object), tx.astype(object)), index=idx, dtype="object")
    dis = mgmt & (sub == 10)
    ev_k = np.concatenate([tx.to_numpy(object)[dis], ra.to_numpy(object)[dis]]); ev_t = np.concatenate([tt[dis], tt[dis]])
    cnt = _count_prior(ev_k, ev_t, dstn.to_numpy(object), tt)
    df["prot_data_after_disas"] = np.where(isdata, cnt, np.nan)

    # (5) eapol_m3_repeat: EAPOL msg-3 from the same TA with the same replay counter in the previous L seconds (this frame not counted)
    if "wlan_rsna_eapol.keydes.msgnr" in raw and "eapol.keydes.replay_counter" in raw:
        msg = to_numeric(raw["wlan_rsna_eapol.keydes.msgnr"]).to_numpy()
        rc = to_numeric(raw["eapol.keydes.replay_counter"])
        m3 = is_eapol.to_numpy() & (msg == 3) & rc.notna().to_numpy() & tx.notna().to_numpy()
        key = pd.Series(pd.NA, index=idx, dtype="object")
        key[m3] = (tx[m3].astype(str) + "|" + rc[m3].astype("int64").astype(str)).astype(object)
        cnt = _count_prior(key.to_numpy(object)[m3], tt[m3], key.to_numpy(object), tt)
        df["eapol_m3_repeat"] = np.where(m3, cnt, np.nan)
    else:
        df["eapol_m3_repeat"] = np.nan


def feature_order(base_features: list[str]) -> list[str]:
    """Every column derive() returns (union of all feature sets). v2 order + CONTEXT appended."""
    return list(base_features) + [MAC_LEN] + DERIVED + INDICATORS + CONTEXT


# Features dropped from the full set to form F2 (the E7 set)
E7_DROP = ["frame.time_delta", "frames_per_sec", "unique_tx_per_sec"]
RSSI = ["wlan_radio.signal_dbm", "rssi_delta_tx"]


C11 = ("mac_len", "wlan_radio.signal_dbm", "wlan.duration", "wlan.fc.type", "wlan.fc.subtype", "wlan.fc.ds", "wlan.fc.frag", "wlan.fc.retry",
       "wlan.fc.pwrmgt", "wlan.fc.moredata", "wlan.fc.protected")


def feature_sets(base_features: list[str]) -> dict[str, list[str]]:
    """F1 Min · F2 E7 · F3 E7-RSSI · F4 E7+context · (F5 = F4-RSSI, created once Tong approves it at P4)"""
    allf = feature_order(base_features)
    f2 = [f for f in allf if f not in E7_DROP and f not in CONTEXT]
    f3 = [f for f in f2 if f not in RSSI]
    f4 = list(f2) + CONTEXT          # Tong approved 2026-10-17: keep eapol_replay_repeat too (eapol_m3_repeat has no signal in AWID3)
    f1 = [MAC_LEN, "wlan.fc.type", "wlan.fc.subtype", "wlan.duration"]
    # C11 (2026-11-11, descriptive baseline only): the 11 of the 16 expert-selected features of Chatzoglou et al. 2022 (IEEE Access 10, Table 2)
    # that the mini PC can capture. frame.len -> mac_len, radiotap.dbm_antsignal -> wlan_radio.signal_dbm; dropped by feature_policy:
    # radiotap.length, radiotap.present.tsft (HW_ARTIFACT), radiotap.channel.freq, radiotap.channel.flags.cck/ofdm (ENV_ARTIFACT)
    c11 = [f for f in allf if f in C11]
    return {"F1": f1, "F2": f2, "F3": f3, "F4": f4, "C11": c11}


# Extra raw columns that must be read (not features, but used to compute derived features / splits)
AUX_RAW_COLUMNS = ["frame.time_epoch", "wlan.seq", "wlan.ta", "wlan.sa",
                   "eapol.keydes.replay_counter", "eapol.type", "wlan.fc.type", "wlan.fc.subtype",
                   "frame.len", "radiotap.length", "wlan.fc.protected",
                   # v3: used only as grouping keys / raw inputs for derive -- must not go into the model directly (IDENTIFIER)
                   "wlan.bssid", "wlan.ssid", "wlan.ra", "wlan.da", "wlan.fixed.timestamp",
                   "wlan_rsna_eapol.keydes.msgnr", "wlan.fc.ds"]
