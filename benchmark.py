import json
import os

def run_benchmarking(classified_file, ground_truth_file, verbose=True):
    if not os.path.exists(ground_truth_file):
        print(f"❌ Error: Ground Truth file not found at {ground_truth_file}")
        return

    with open(ground_truth_file, 'r', encoding='utf-8') as f:
        gt = json.load(f)

    correct_labels = 0
    total_items = 0
    llm_true_positives = 0
    false_positives_kept = 0
    missed_secrets = 0
    
    # Track misclassified items for debugging
    missed_secrets_list = []
    false_positives_list = []
    not_found_in_gt = []

    if not os.path.exists(classified_file):
        print(f"❌ Error: Classified findings file not found at {classified_file}")
        return

    with open(classified_file, 'r', encoding='utf-8') as f:
        for line_num, line in enumerate(f, 1):
            if not line.strip():
                continue

            finding = json.loads(line)

            snippet = finding.get("snippet")
            llm_label = finding.get("_llm_label", "SKIPPED")
            llm_explanation = finding.get("_llm_explanation", "")
            rule = finding.get("rule", "unknown")
            matched_data = finding.get("matched_data", "")

            llm_normalized = llm_label.replace("_", " ")
            gt_label = gt.get(snippet)

            if not gt_label:
                not_found_in_gt.append({
                    "line": line_num,
                    "snippet": snippet,
                    "llm_label": llm_normalized
                })
                continue

            total_items += 1

            # 1. Matching Accuracy
            if llm_normalized == gt_label:
                correct_labels += 1

            # 2. False Positive tracking
            if llm_normalized == "TRUE POSITIVE":
                llm_true_positives += 1
                if gt_label == "FALSE POSITIVE":
                    false_positives_kept += 1
                    false_positives_list.append({
                        "line": line_num,
                        "rule": rule,
                        "snippet": snippet[:80],
                        "matched_data": matched_data[:60],
                        "llm_said": llm_normalized,
                        "ground_truth": gt_label,
                        "llm_reason": llm_explanation
                    })

            # 3. Missed secrets
            if gt_label == "TRUE POSITIVE" and llm_normalized != "TRUE POSITIVE":
                missed_secrets += 1
                missed_secrets_list.append({
                    "line": line_num,
                    "rule": rule,
                    "snippet": snippet[:80],
                    "matched_data": matched_data[:60],
                    "llm_said": llm_normalized,
                    "ground_truth": gt_label,
                    "llm_reason": llm_explanation
                })

    # --- Calculations ---
    match_accuracy = (correct_labels / total_items) * 100 if total_items > 0 else 0
    fp_rate = (false_positives_kept / llm_true_positives) * 100 if llm_true_positives > 0 else 0

    # --- Print Report ---
    print(f"\n{'='*70}")
    print(f"                    BENCHMARK PERFORMANCE REPORT")
    print(f"{'='*70}")
    print(f"\n📊 METRICS:")
    print(f"  Total Evaluated Items:    {total_items}")
    print(f"  Matching Accuracy:        {match_accuracy:.2f}%")
    print(f"  False Positive Rate:      {fp_rate:.2f}% (Target: <5%)")

    print(f"\n📈 BREAKDOWN:")
    print(f"  Correct Classifications:  {correct_labels}")
    print(f"  Missed Secrets (FN):      {missed_secrets} {'🚨 CRITICAL!' if missed_secrets > 0 else '✓'}")
    print(f"  Noise Leaked (FP):        {false_positives_kept}")

    if verbose and missed_secrets_list:
        print(f"\n{'='*70}")
        print(f"🚨 MISSED SECRETS")
        print(f"{'='*70}")
        for i, item in enumerate(missed_secrets_list, 1):
            print(f"\n  [{i}] Line {item['line']} | Rule: {item['rule']}")
            print(f"      Snippet: {item['snippet']}...")
            print(f"      Value:   {item['matched_data']}...")
            print(f"      LLM Reason: {item['llm_reason']}")

    if verbose and false_positives_list:
        print(f"\n{'='*70}")
        print(f"⚠️  NOISE LEAKED")
        print(f"{'='*70}")
        for i, item in enumerate(false_positives_list, 1):
            print(f"\n  [{i}] Line {item['line']} | Rule: {item['rule']}")
            print(f"      Snippet: {item['snippet']}...")
            print(f"      Value:   {item['matched_data']}...")
            print(f"      LLM Reason: {item['llm_reason']}")

    if verbose and not_found_in_gt:
        print(f"\n{'='*70}")
        print(f"❓ NOT FOUND IN GROUND TRUTH ({len(not_found_in_gt)} items)")
        print(f"{'='*70}")
        for item in not_found_in_gt[:10]:
            print(f"  Line {item['line']}: {item['snippet'][:60]}...")
        if len(not_found_in_gt) > 10:
            print(f"  ... and {len(not_found_in_gt) - 10} more")

    print(f"\n{'='*70}")

    return {
        "accuracy": match_accuracy,
        "fp_rate": fp_rate,
        "missed_secrets": missed_secrets_list,
        "false_positives": false_positives_list
    }


if __name__ == "__main__":
    run_benchmarking(
        'classified_findings.jsonl',
        '../test_final/ground_truth.json'
    )
