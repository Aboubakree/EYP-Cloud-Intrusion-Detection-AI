"""
evaluate_per_attack.py
──────────────────────────────────────────────────────────────────────────
The defence centerpiece.

Runs the CICIDS-2017-trained Random Forest against traffic generated on
YOUR OWN lab VMs — one capture per attack type, each auto-labelled by what
was running when it was captured. Produces a per-attack detection table
that quantifies exactly which attacks the benchmark-trained model catches
and which it misses.

This is the evidence for the generalization-gap finding.

Usage:
    python3 evaluate_per_attack.py <folder_with_csvs>

Example:
    python3 evaluate_per_attack.py /mnt/lab-project/ids-project/experimental_attack
──────────────────────────────────────────────────────────────────────────
"""
import sys
import json
import time
import joblib
import warnings
import numpy as np
import pandas as pd
from pathlib import Path
import sys

warnings.filterwarnings("ignore")

# ── Paths ─────────────────────────────────────────────────────────────────────
PROJECT   = Path(__file__).resolve().parents[1]
# print(PROJECT)
# sys.exit()
MODEL_DIR = PROJECT / "models"
OUT_DIR   = PROJECT / "reports" / "results"
OUT_DIR.mkdir(parents=True, exist_ok=True)

MODEL_FILE    = MODEL_DIR / "detector_rf.joblib"
METADATA_FILE = MODEL_DIR / "model_metadata.json"

# ── Map each capture file to its ground-truth label ───────────────────────────
# Each file was captured in isolation, so every flow in it is that one type.
# "benign" is the only file where flagged flows are FALSE POSITIVES.
FILE_LABELS = {
    "benign.pcap_Flow.csv":    ("Benign traffic",    "benign"),
    "ssh_brute.pcap_Flow.csv": ("SSH brute force",   "attack"),
    "portscan.pcap_Flow.csv":  ("Port scan",         "attack"),
    "synflood.pcap_Flow.csv":  ("SYN flood (DoS)",   "attack"),
}

# ── CICFlowMeter v4 → CICIDS-2017 training renames ────────────────────────────
RENAME_V4_TO_TRAIN = {
    "Dst Port":                    "Destination Port",
    "Total Fwd Packet":            "Total Fwd Packets",
    "Total Bwd packets":           "Total Backward Packets",
    "Total Length of Fwd Packet":  "Total Length of Fwd Packets",
    "Total Length of Bwd Packet":  "Total Length of Bwd Packets",
    "Packet Length Min":           "Min Packet Length",
    "Packet Length Max":           "Max Packet Length",
    "FWD Init Win Bytes":          "Init_Win_bytes_forward",
    "Bwd Init Win Bytes":          "Init_Win_bytes_backward",
    "Fwd Act Data Pkts":           "act_data_pkt_fwd",
    "Fwd Seg Size Min":            "min_seg_size_forward",
}

# Reading the 672 MB SYN-flood CSV in chunks keeps memory flat
CHUNK_SIZE = 200_000


def add_engineered_features(d: pd.DataFrame) -> pd.DataFrame:
    """Identical to the training notebook — flows must be built the same way."""
    d = d.copy()
    eps = 1e-6
    if {"Total Fwd Packets", "Total Backward Packets"}.issubset(d.columns):
        d["fwd_bwd_pkt_ratio"] = d["Total Fwd Packets"] / (d["Total Backward Packets"] + eps)
    if {"Total Length of Fwd Packets", "Total Length of Bwd Packets"}.issubset(d.columns):
        d["fwd_bwd_byte_ratio"] = (d["Total Length of Fwd Packets"] /
                                   (d["Total Length of Bwd Packets"] + eps))
    if {"Total Length of Fwd Packets", "Total Fwd Packets"}.issubset(d.columns):
        d["avg_fwd_pkt_size"] = d["Total Length of Fwd Packets"] / (d["Total Fwd Packets"] + eps)
    return d


def prepare_chunk(df: pd.DataFrame, feature_order: list):
    """Rename → engineer → clean → align to feature_order. Returns (X, n_dropped)."""
    df.columns = df.columns.str.strip()
    df = df.rename(columns=RENAME_V4_TO_TRAIN)
    df = add_engineered_features(df)
    df = df.replace([np.inf, -np.inf], np.nan)

    missing = [f for f in feature_order if f not in df.columns]
    if missing:
        raise ValueError(f"Missing features after rename: {missing}")

    X = df[feature_order].copy()
    before = len(X)
    X = X[~X.isnull().any(axis=1)]
    return X, before - len(X)


def evaluate_file(path: Path, model, feature_order: list):
    """Stream a CSV through the model in chunks, return aggregate counts."""
    total, flagged, dropped = 0, 0, 0
    proba_sum, proba_max = 0.0, 0.0
    t0 = time.time()

    for chunk in pd.read_csv(path, chunksize=CHUNK_SIZE, low_memory=False):
        X, nd = prepare_chunk(chunk, feature_order)
        dropped += nd
        if len(X) == 0:
            continue
        preds  = model.predict(X.values)
        probas = model.predict_proba(X.values)[:, 1]
        total   += len(X)
        flagged += int((preds == 1).sum())
        proba_sum += float(probas.sum())
        proba_max = max(proba_max, float(probas.max()) if len(probas) else 0.0)

    elapsed = time.time() - t0
    return {
        "total":      total,
        "flagged":    flagged,
        "dropped":    dropped,
        "mean_proba": (proba_sum / total) if total else 0.0,
        "max_proba":  proba_max,
        "elapsed":    elapsed,
    }


def main():
    if len(sys.argv) != 2:
        print("Usage: python3 evaluate_per_attack.py <folder_with_csvs>")
        sys.exit(1)

    folder = Path(sys.argv[1])
    if not folder.is_dir():
        print(f"[ERROR] Not a folder: {folder}")
        sys.exit(1)

    # ── Load model + contract ────────────────────────────────────────────────
    print("=" * 74)
    print("  PER-ATTACK EVALUATION : CICIDS-2017 model vs our own lab traffic")
    print("=" * 74)

    model = joblib.load(MODEL_FILE)
    meta  = json.load(open(METADATA_FILE))
    feature_order = meta["feature_order"]
    print(f"  Model   : {MODEL_FILE.name}  ({meta.get('winner','?')})")
    print(f"  Features: {len(feature_order)}")
    print(f"  Source  : {folder}\n")

    # ── Evaluate each capture ────────────────────────────────────────────────
    rows = []
    for fname, (nice_name, kind) in FILE_LABELS.items():
        fpath = folder / fname
        if not fpath.exists():
            print(f"  [skip] {fname} not found")
            continue

        size_mb = fpath.stat().st_size / 1e6
        print(f"  Processing {nice_name:<18} ({size_mb:,.0f} MB)...", flush=True)
        r = evaluate_file(fpath, model, feature_order)

        detected_pct = (r["flagged"] / r["total"] * 100) if r["total"] else 0.0
        rows.append({
            "Traffic type": nice_name,
            "Ground truth": kind,
            "Flows":        r["total"],
            "Flagged attack": r["flagged"],
            "Rate %":       round(detected_pct, 2),
            "Mean proba":   round(r["mean_proba"], 3),
            "Max proba":    round(r["max_proba"], 3),
            "Dropped":      r["dropped"],
        })
        print(f"      → {r['total']:,} flows, {r['flagged']:,} flagged "
              f"({detected_pct:.2f}%), {r['elapsed']:.1f}s\n")

    if not rows:
        print("No files processed.")
        sys.exit(1)

    results = pd.DataFrame(rows)

    # ── The results table ────────────────────────────────────────────────────
    print("=" * 74)
    print("  RESULTS TABLE")
    print("=" * 74)

    display = results.copy()
    display["Flows"]          = display["Flows"].map("{:,}".format)
    display["Flagged attack"] = display["Flagged attack"].map("{:,}".format)
    print(display.to_string(index=False))

    # ── Interpretation ───────────────────────────────────────────────────────
    print("\n" + "=" * 74)
    print("  READING THE TABLE")
    print("=" * 74)

    for r in rows:
        name = r["Traffic type"]
        rate = r["Rate %"]
        if r["Ground truth"] == "benign":
            print(f"  {name:<18} → {rate:.2f}% flagged = FALSE POSITIVE RATE "
                  f"(lower is better)")
        else:
            if rate >= 80:
                verdict = "DETECTED well — this attack transfers"
            elif rate >= 30:
                verdict = "PARTIALLY detected — weak transfer"
            else:
                verdict = "MISSED — the generalization gap"
            print(f"  {name:<18} → {rate:.2f}% detected = {verdict}")

    # ── Save outputs for the thesis ──────────────────────────────────────────
    csv_out = OUT_DIR / "per_attack_results.csv"
    results.to_csv(csv_out, index=False)

    # LaTeX table for direct paste into Chapter 5
    latex_out = OUT_DIR / "per_attack_results.tex"
    with open(latex_out, "w") as f:
        f.write(results_to_latex(results))

    print("\n" + "=" * 74)
    print(f"  Saved: {csv_out}")
    print(f"  Saved: {latex_out}")
    print("=" * 74)


def results_to_latex(df: pd.DataFrame) -> str:
    """Build a clean booktabs LaTeX table."""
    lines = [
        r"\begin{table}[h]",
        r"\centering",
        r"\caption{Detection results on independently generated lab traffic. "
        r"Each capture was produced in isolation on the lab VMs, so every flow "
        r"is ground-truth labelled by the attack that generated it.}",
        r"\label{tab:per-attack-results}",
        r"\begin{tabular}{lrrrr}",
        r"\toprule",
        r"Traffic type & Flows & Flagged & Rate (\%) & Max prob. \\",
        r"\midrule",
    ]
    for _, row in df.iterrows():
        lines.append(
            f"{row['Traffic type']} & {row['Flows']:,} & "
            f"{row['Flagged attack']:,} & {row['Rate %']:.2f} & "
            f"{row['Max proba']:.3f} \\\\"
        )
    lines += [r"\bottomrule", r"\end{tabular}", r"\end{table}"]
    return "\n".join(lines)


if __name__ == "__main__":
    main()
