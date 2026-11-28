# LightGBM WIDS model: inference trial on the mini PC

The one model that passed the offline test gate and goes on to field testing:
LightGBM, 8 classes, feature set F4 with window-relative RSSI, trained on AWID3.

## Run

Python 3.9 to 3.12. On Debian/Ubuntu, LightGBM also needs `libgomp1`.

```bash
cd POC_Tong/lightgbm_p6
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python infer.py /path/to/capture.csv.gz      # writes predictions.csv
```

Add `--threads 2` to use two cores. At the end `infer.py` prints the time taken,
windows per second and peak memory.

## Input

The sensor's capture CSV (or `.csv.gz`), one row per 802.11 frame, with
Wireshark field names as column headers. Extra columns are ignored.
`frame.time_epoch`, `frame.len`, `radiotap.length`, `wlan.fc.type` and
`wlan.fc.subtype` are required; any other missing column is treated as empty and
listed on screen. One file is one session, and the whole file is processed at once.

## Output

One row per window (50 frames, a new window every 25 frames): `t_start`,
`t_end`, `pred_class` and a probability for each class. Classes: Normal, Deauth,
Disas, (Re)Assoc, RogueAP, Krack, Kr00k, Evil_Twin.

## What to expect

This trial checks that the model **runs** on the mini PC. Do not raise alerts
from its predictions yet.

| Measured on | Result |
|---|---|
| AWID3 offline test, this model (seed 1) | Macro-F1 0.885 |
| AWID3 offline test, mean of 3 seeds | Macro-F1 0.848 (0.825 to 0.885) |
| External WPA3 dataset, mean of 3 seeds | recall: Deauth 0.14, Disas 0.74, RogueAP 0.00, Evil_Twin 0.00 |
| External WPA3 dataset, normal traffic | false positives 0.5% to 21% of windows per file, mostly predicted Krack |

- Seed 1 is the seed with the highest test score, so 0.885 is optimistic. The
  formal field evaluation averages seeds 0 to 2; only seed 1 is included here.
- Not yet evaluated on our own network. In a smoke run on one 2-minute sensor
  capture, 549 of 556 windows were predicted Evil_Twin, so expect false positives.
- The first 5 seconds of each file have less history for some features.

## Files

| Path | What it is |
|---|---|
| `infer.py` | capture file to predictions |
| `features.py` | per-frame features, copied unchanged from the training code |
| `model/lightgbm_seed1.txt` | LightGBM model (native text format) |
| `model/preprocess.json` | feature order, scaler mean and std, window size, class names |
