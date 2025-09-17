import json
from collections import defaultdict
import os

RESULTS_PATH = os.path.join(os.path.dirname(__file__), "gemini_analysis_test_results.json")

if not os.path.exists(RESULTS_PATH):
    raise SystemExit(f"Results file not found: {RESULTS_PATH}. Run analyzer and move JSON there.")

with open(RESULTS_PATH, "r") as f:
    model_results = json.load(f)

# Ground truth mapping for your five test files
GROUND_TRUTH = {
    "sql_injection.py": [
        {"type": "SQL_INJECTION", "line": 9}
    ],
    "hardcoded_secrets.py": [
        {"type": "HARDCODED_SECRETS", "line": 5},
        {"type": "HARDCODED_SECRETS", "line": 6}
    ],
    "command_injection.py": [
        {"type": "COMMAND_INJECTION", "line": 8},
        {"type": "COMMAND_INJECTION", "line": 11}
    ],
    "weak_crypto.py": [
        {"type": "WEAK_CRYPTO", "line": 7},
        {"type": "WEAK_RANDOM", "line": 13}
    ],
    "insecure_deserialization.py": [
        {"type": "INSECURE_DESERIALIZATION", "line": 7},
        {"type": "INSECURE_DESERIALIZATION", "line": 12}
    ]
}

def norm(t):
    return t.strip().upper()

# model_results expected format: {test_name: analysis_result}
predictions = []
for key, analysis in model_results.items():
    # analysis might be the direct object or nested; normalize
    if isinstance(analysis, dict):
        filename = analysis.get("metadata", {}).get("filename") or analysis.get("file") or key
        vulns = analysis.get("vulnerabilities") or []
    else:
        filename = key
        vulns = []
    for v in vulns:
        predictions.append({
            "file": os.path.basename(filename),
            "type": norm(v.get("vulnerability_type") or v.get("type", "")),
            "line": int(v.get("line_number") or v.get("line") or -1)
        })

gtruth_list = []
for fname, items in GROUND_TRUTH.items():
    for it in items:
        gtruth_list.append({
            "file": fname,
            "type": norm(it["type"]),
            "line": int(it["line"])
        })

def match_pred_to_gt(pred, gt):
    if pred["file"] == gt["file"] or pred["file"].endswith(gt["file"]) or gt["file"].endswith(pred["file"]):
        if pred["type"] == gt["type"]:
            if abs(pred["line"] - gt["line"]) <= 1:  # tolerance
                return True
    return False

tp = 0
fp = 0
used_gt = set()
for p in predictions:
    matched = False
    for i, g in enumerate(gtruth_list):
        if i in used_gt:
            continue
        if match_pred_to_gt(p, g):
            tp += 1
            used_gt.add(i)
            matched = True
            break
    if not matched:
        fp += 1

fn = len(gtruth_list) - len(used_gt)
precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0

print("=== SCORING RESULTS ===")
print(f"TP: {tp}, FP: {fp}, FN: {fn}")
print(f"Precision: {precision:.3f}")
print(f"Recall:    {recall:.3f}")
print(f"F1-score:  {f1:.3f}")

if fp > 0:
    print("\nPotential hallucinations (predicted but not matched):")
    for p in predictions:
        matched_any = any(match_pred_to_gt(p, g) for g in gtruth_list)
        if not matched_any:
            print(f" - {p}")
