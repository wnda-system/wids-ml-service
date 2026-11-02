"""Model C input features, computed only from features.windows() output (FEATURE_VERSION 2).

Pure numpy/pandas, no file access, no state: the sensor calls model_features()
on each new batch of per-second windows.
"""
import numpy as np
import pandas as pd

FEATURE_VERSION = 2

# windows() columns that describe an attack directly and don't scale with how
# busy the site is (plan section 4)
DIRECT = [
    "deauth", "disassoc", "auth", "assoc_req", "deauth_to_one_client_10s",
    "deauth_seq_out_of_order", "tsf_offset_switches", "new_bssid_known_ssid",
    "max_bssid_per_ssid", "bssid_beacon_rate", "arp_ip_mac_flips_10s",
    "arp_ips_per_mac_60s", "arp_reply_ratio", "retry_ratio", "protected_ratio",
]

# shares instead of raw counts: name -> (numerator, denominator)
RATIOS = {
    "mgmt_frac": ("mgmt", "frames"), "ctrl_frac": ("ctrl", "frames"), "data_frac": ("data", "frames"),
    "deauth_per_mgmt": ("deauth", "mgmt"), "beacon_per_mgmt": ("beacon", "mgmt"),
    "probe_req_per_mgmt": ("probe_req", "mgmt"), "rts_per_ctrl": ("rts", "ctrl"),
    "cts_per_ctrl": ("cts", "ctrl"),
}

CANDIDATES = DIRECT + list(RATIOS)

# Dropped after comparing AWID3 normal seconds with our own (notes/step4_feature_compare.md):
#   arp_*            always 0 in AWID3 (ARP is encrypted there), non-zero in 10-17% of ours
#   mgmt/ctrl/data_frac, protected_ratio, retry_ratio
#                    median differs 3-127x between the two sites even as shares
#   max_bssid_per_ssid  1 in AWID3 vs 3 in ours (multi-AP enterprise SSIDs); the
#                    evil-twin value (2) is below our normal
DROPPED = ["arp_ip_mac_flips_10s", "arp_ips_per_mac_60s", "arp_reply_ratio", "mgmt_frac", "ctrl_frac",
           "data_frac", "protected_ratio", "retry_ratio", "max_bssid_per_ssid"]

# final model input, in order (must equal meta.json["features"])
FEATURES = [c for c in CANDIDATES if c not in DROPPED]


def all_candidates(win_df: pd.DataFrame) -> pd.DataFrame:
    out = pd.DataFrame(index=win_df.index)
    for c in DIRECT:
        out[c] = win_df[c].astype(float)
    for name, (num, den) in RATIOS.items():
        out[name] = win_df[num].astype(float) / win_df[den].astype(float).replace(0, np.nan)
    return out.replace([np.inf, -np.inf], np.nan).fillna(0.0)


def model_features(win_df: pd.DataFrame) -> pd.DataFrame:
    return all_candidates(win_df)[FEATURES]
