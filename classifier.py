"""
SECRET CLASSIFIER v4.1 - LLM-First with Parallel Processing
============================================================
Same classification logic as v4.0, but with ThreadPoolExecutor
for ~10x speedup on large batches.

Classification accuracy is IDENTICAL - only execution is parallelized.
"""

import os
import json
import time
from typing import Dict, Tuple, List
from concurrent.futures import ThreadPoolExecutor, as_completed
from openai import OpenAI

client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

# =============================================================================
# CONFIGURATION
# =============================================================================

MAX_WORKERS = 10  # Concurrent API calls (OpenAI allows ~3500 req/min for gpt-4o-mini)

# =============================================================================
# GENERAL CLASSIFICATION PROMPT (UNCHANGED)
# =============================================================================

SYSTEM_PROMPT = """You are a senior security engineer reviewing code for leaked credentials.

Your task is to determine if a detected pattern represents a REAL secret that poses security risk, or a FALSE POSITIVE that is safe to ignore.

## How to Think About This Problem

### What Makes a Secret REAL (TRUE_POSITIVE)?
A real secret is one that could grant unauthorized access if exposed:
- It has sufficient entropy/randomness to be cryptographically useful
- It follows a format that would actually work with a service
- The context suggests production use (config files, environment variables, actual assignments)

### What Makes a Secret FAKE (FALSE_POSITIVE)?
A fake secret is intentionally non-functional:
- The variable name explicitly indicates testing purpose (test_, mock_, dummy_, demo_, example_, fake_, sample_)
- The value itself is obviously placeholder data:
  * All same characters (000000, aaaaaa)
- Development/local environment indicators (localhost, 127.0.0.1) for connection strings
- Comments or documentation describing secrets (not containing them)
- Code that references secrets but doesn't contain them (function names, imports, comparisons)

CRITICAL OVERRIDE RULE:
- Password simplicity is NEVER a reason to mark FALSE_POSITIVE.
- Common passwords (e.g., "password", "password123", "admin123", "qwerty") 
  MUST be labeled TRUE_POSITIVE IF they appear in a real assignment, 
  config, env var, or production-like context.
- Treat weak passwords as MORE dangerous, not less.

### Key Decision Principles
1. **Context matters most**: A valid-looking key in a variable named "test_api_key" is likely fake
2. **Format alone isn't enough**: Even well-formatted keys can be test data
3. **When truly uncertain, lean toward TRUE_POSITIVE**: Missing a real secret is worse than flagging a fake one
4. **Production indicators override test suspicions**: Real config files, env vars, or deployment code = likely real
5. **Many REAL API keys contain sequential-looking characters:
    - `key-abcdefghijklmnopqrstuvwxyz123456` → TRUE_POSITIVE (valid Mailgun format)
    - `ACabcdefghijklmnopqrstuvwxyz012345` → TRUE_POSITIVE (valid Twilio SID format)
    - `sk_live_abc123abc123abc123abc123` → TRUE_POSITIVE (valid Stripe format)
    - `Basic dXNlcm5hbWU6cGFzc3dvcmQ=` → TRUE_POSITIVE (valid Base64 auth)
    - `password123!` → TRUE_POSITIVE (common but real password, simple does not mean fake) 


**DO NOT mark as FALSE_POSITIVE just because the value contains abc, 123, or sequential characters.**


## Response Format
Respond with a JSON object:
{
  "label": "TRUE_POSITIVE" or "FALSE_POSITIVE",
  "reason": "Brief 2-3 sentence explanation of your decision"
}

Keep the reason concise but informative - it should explain WHY you made that decision."""


USER_PROMPT_TEMPLATE = """Analyze this detected credential:

**Rule Matched:** {rule}
**Code Context:** {snippet}  
**Extracted Value:** {matched_data}
**Scanner Confidence:** {confidence}

Is this a real secret (TRUE_POSITIVE) or test/fake data (FALSE_POSITIVE)?"""


# =============================================================================
# PRE-FILTER (UNCHANGED)
# =============================================================================

def quick_prefilter(finding: Dict) -> Tuple[bool, str, str]:
    """
    Quick check for VERY obvious cases only.
    Returns: (should_skip_llm, label, reason)
    
    Only filters cases where LLM would definitely agree.
    """
    snippet = finding.get("snippet", "").lower()
    matched = finding.get("matched_data", "").lower()
    rule = finding.get("rule", "")
    
    # Case 1: Private keys are almost always TRUE_POSITIVE
    # (except explicit test file mention which LLM should handle)
    if rule in ["rsa_private_key", "dsa_private_key", "ec_private_key"]:
        if "(in a file named test" not in snippet:
            return True, "TRUE_POSITIVE", "Private key block detected - always flag"
    
    # Case 2: All-zeros placeholder (obvious fake)
    clean = matched.replace('-', '').replace('_', '').replace('.', '').replace('=', '')
    if len(clean) > 10 and all(c == '0' for c in clean):
        return True, "FALSE_POSITIVE", "All-zeros placeholder pattern"
    
    # Case 3: Localhost connection strings (obvious dev environment)
    if rule in ["mongodb_connection", "postgres_connection", "mysql_connection"]:
        if "localhost" in snippet or "127.0.0.1" in snippet:
            return True, "FALSE_POSITIVE", "Localhost database connection - dev environment"
    
    # Everything else goes to LLM
    return False, "", ""


# =============================================================================
# SINGLE CLASSIFICATION (UNCHANGED LOGIC)
# =============================================================================

def classify_finding(finding: Dict, model: str = "gpt-4o-mini") -> Dict:
    """
    Classify a finding using LLM with general prompt.
    Returns finding with _llm_label, _llm_confidence, _llm_explanation added.
    
    This function is UNCHANGED from v4.0 - same prompt, same logic.
    """
    
    user_prompt = USER_PROMPT_TEMPLATE.format(
        rule=finding.get("rule", "unknown"),
        snippet=finding.get("snippet", "")[:200],
        matched_data=finding.get("matched_data", "")[:150],
        confidence=finding.get("confidence", "unknown")
    )
    
    try:
        response = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt}
            ],
            temperature=0.1,  # Low but not zero for slightly better reasoning
            max_tokens=100,
            response_format={"type": "json_object"}
        )
        
        result = json.loads(response.choices[0].message.content)
        label = result.get("label", "TRUE_POSITIVE").upper()
        reason = result.get("reason", "No explanation provided")
        
        # Normalize label
        if "TRUE" in label:
            label = "TRUE_POSITIVE"
        elif "FALSE" in label:
            label = "FALSE_POSITIVE"
        else:
            label = "TRUE_POSITIVE"  # Default safe
            
        return {
            "_llm_label": label,
            "_llm_confidence": 0.9,
            "_llm_explanation": reason
        }
        
    except json.JSONDecodeError:
        # If JSON parsing fails, try to extract from text
        text = response.choices[0].message.content.upper()
        if "FALSE" in text:
            return {"_llm_label": "FALSE_POSITIVE", "_llm_confidence": 0.7, "_llm_explanation": "JSON parse error - extracted from text"}
        return {"_llm_label": "TRUE_POSITIVE", "_llm_confidence": 0.7, "_llm_explanation": "JSON parse error - defaulting safe"}
        
    except Exception as e:
        return {"_llm_label": "TRUE_POSITIVE", "_llm_confidence": 0.5, "_llm_explanation": f"Error: {str(e)[:50]}"}


# =============================================================================
# PARALLEL CLASSIFICATION WORKER
# =============================================================================

def classify_single(args: Tuple[int, Dict, bool]) -> Tuple[int, Dict]:
    """
    Worker function for parallel processing.
    
    Args:
        args: Tuple of (index, finding, use_prefilter)
    
    Returns:
        Tuple of (index, classified_finding) to maintain order
    """
    index, finding, use_prefilter = args
    
    # Try prefilter first
    if use_prefilter:
        skip_llm, label, reason = quick_prefilter(finding)
        if skip_llm:
            finding["_llm_label"] = label
            finding["_llm_confidence"] = 0.95
            finding["_llm_explanation"] = reason
            finding["_prefiltered"] = True
            return (index, finding)
    
    # Send to LLM (same logic as before)
    llm_result = classify_finding(finding)
    finding.update(llm_result)
    finding["_prefiltered"] = False
    
    return (index, finding)


# =============================================================================
# PARALLEL BATCH PROCESSING
# =============================================================================

def process_findings_parallel(
    input_file: str, 
    output_file: str, 
    use_prefilter: bool = True,
    max_workers: int = MAX_WORKERS,
    show_progress: bool = True
):
    """
    Process all findings with PARALLEL LLM classification.
    
    Same classification logic as sequential version, but ~10x faster.
    
    Args:
        input_file: Path to scanner_findings.jsonl
        output_file: Path to save classified results
        use_prefilter: Enable prefilter for obvious cases
        max_workers: Number of concurrent threads (default: 10)
        show_progress: Print progress updates
    """
    if not os.path.exists(input_file):
        print(f"❌ Error: {input_file} not found")
        return

    # Load findings
    findings = []
    with open(input_file, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                findings.append(json.loads(line))
    
    total = len(findings)
    print(f"📂 Loaded {total} findings")
    print(f"🔧 Pre-filter enabled: {use_prefilter}")
    print(f"🚀 Parallel workers: {max_workers}")
    print(f"{'='*60}\n")
    
    start_time = time.time()
    
    # Prepare tasks: (index, finding, use_prefilter)
    tasks = [(i, finding, use_prefilter) for i, finding in enumerate(findings)]
    
    # Process in parallel
    results = [None] * total  # Pre-allocate to maintain order
    stats = {"prefiltered": 0, "llm_calls": 0, "tp": 0, "fp": 0, "completed": 0}
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submit all tasks
        future_to_index = {
            executor.submit(classify_single, task): task[0] 
            for task in tasks
        }
        
        # Collect results as they complete
        for future in as_completed(future_to_index):
            try:
                index, classified_finding = future.result()
                results[index] = classified_finding
                
                # Update stats
                stats["completed"] += 1
                if classified_finding.get("_prefiltered"):
                    stats["prefiltered"] += 1
                else:
                    stats["llm_calls"] += 1
                
                if classified_finding["_llm_label"] == "TRUE_POSITIVE":
                    stats["tp"] += 1
                else:
                    stats["fp"] += 1
                
                # Progress update
                if show_progress and stats["completed"] % 10 == 0:
                    elapsed = time.time() - start_time
                    rate = stats["completed"] / elapsed
                    remaining = (total - stats["completed"]) / rate if rate > 0 else 0
                    print(f"  ⏳ {stats['completed']}/{total} ({rate:.1f}/sec, ~{remaining:.0f}s remaining)")
                    
            except Exception as e:
                index = future_to_index[future]
                print(f"  ⚠️  Error processing finding {index}: {e}")
                # Mark as TRUE_POSITIVE on error (safe default)
                findings[index]["_llm_label"] = "TRUE_POSITIVE"
                findings[index]["_llm_confidence"] = 0.5
                findings[index]["_llm_explanation"] = f"Thread error: {str(e)[:50]}"
                results[index] = findings[index]
                stats["tp"] += 1
                stats["completed"] += 1

    elapsed_time = time.time() - start_time
    
    # Save results (maintaining original order)
    with open(output_file, "w", encoding="utf-8") as f:
        for res in results:
            # Remove internal tracking field
            if "_prefiltered" in res:
                del res["_prefiltered"]
            f.write(json.dumps(res, ensure_ascii=False) + "\n")
    
    # Summary
    print(f"\n{'='*60}")
    print(f"📊 CLASSIFICATION COMPLETE")
    print(f"{'='*60}")
    print(f"Total findings:     {total}")
    print(f"Pre-filtered:       {stats['prefiltered']}")
    print(f"LLM API calls:      {stats['llm_calls']}")
    print(f"Classified TRUE:    {stats['tp']}")
    print(f"Classified FALSE:   {stats['fp']}")
    print(f"{'='*60}")
    print(f"⏱️  Total time:       {elapsed_time:.1f} seconds")
    print(f"⚡ Speed:            {total/elapsed_time:.1f} findings/second")
    print(f"💾 Output saved:     {output_file}")
    
    # Compare to sequential estimate
    sequential_estimate = stats["llm_calls"] * 0.5  # ~0.5s per API call
    speedup = sequential_estimate / elapsed_time if elapsed_time > 0 else 0
    print(f"\n📈 Estimated speedup: {speedup:.1f}x faster than sequential")


# =============================================================================
# ORIGINAL SEQUENTIAL PROCESSING (kept for comparison/fallback)
# =============================================================================

def process_findings_sequential(input_file: str, output_file: str, use_prefilter: bool = True):
    """
    Original sequential processing - same as v4.0.
    Use this if you need to debug or have rate limiting issues.
    """
    if not os.path.exists(input_file):
        print(f"❌ Error: {input_file} not found")
        return

    # Load findings
    findings = []
    with open(input_file, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                findings.append(json.loads(line))
    
    print(f"📂 Loaded {len(findings)} findings")
    print(f"🔧 Pre-filter enabled: {use_prefilter}")
    print(f"🐢 Running in SEQUENTIAL mode\n")
    
    start_time = time.time()
    stats = {"total": 0, "prefiltered": 0, "llm_calls": 0, "tp": 0, "fp": 0}
    results = []
    
    for i, finding in enumerate(findings):
        stats["total"] += 1
        rule = finding.get("rule", "unknown")
        
        # Try prefilter first
        if use_prefilter:
            skip_llm, label, reason = quick_prefilter(finding)
            if skip_llm:
                stats["prefiltered"] += 1
                finding["_llm_label"] = label
                finding["_llm_confidence"] = 0.95
                finding["_llm_explanation"] = reason
                results.append(finding)
                
                if label == "TRUE_POSITIVE":
                    stats["tp"] += 1
                else:
                    stats["fp"] += 1
                continue
        
        # Send to LLM
        print(f"[{i+1}/{len(findings)}] {rule[:30]}...", end=" ")
        stats["llm_calls"] += 1
        
        llm_result = classify_finding(finding)
        finding.update(llm_result)
        
        label = llm_result["_llm_label"]
        reason = llm_result["_llm_explanation"]
        
        print(f"→ {label} | {reason[:40]}...")
        
        if label == "TRUE_POSITIVE":
            stats["tp"] += 1
        else:
            stats["fp"] += 1
        
        results.append(finding)
        time.sleep(0.25)  # Rate limiting

    elapsed_time = time.time() - start_time

    # Save results
    with open(output_file, "w", encoding="utf-8") as f:
        for res in results:
            f.write(json.dumps(res, ensure_ascii=False) + "\n")
    
    # Summary
    print(f"\n{'='*60}")
    print(f"📊 CLASSIFICATION COMPLETE (Sequential)")
    print(f"{'='*60}")
    print(f"Total findings:     {stats['total']}")
    print(f"Pre-filtered:       {stats['prefiltered']}")
    print(f"LLM API calls:      {stats['llm_calls']}")
    print(f"Classified TRUE:    {stats['tp']}")
    print(f"Classified FALSE:   {stats['fp']}")
    print(f"⏱️  Total time:       {elapsed_time:.1f} seconds")
    print(f"Output saved:       {output_file}")


# =============================================================================
# CONVENIENCE FUNCTION FOR LISTS (used by web server)
# =============================================================================

def classify_findings_batch(
    findings: List[Dict], 
    use_prefilter: bool = True,
    max_workers: int = MAX_WORKERS
) -> List[Dict]:
    """
    Classify a list of findings in parallel.
    
    This is the function to use from web servers or other code.
    Returns the same list with classification results added.
    
    Args:
        findings: List of finding dictionaries
        use_prefilter: Enable prefilter for obvious cases
        max_workers: Number of concurrent threads
    
    Returns:
        List of findings with _llm_label, _llm_confidence, _llm_explanation added
    """
    if not findings:
        return []
    
    total = len(findings)
    results = [None] * total
    
    # Prepare tasks
    tasks = [(i, finding.copy(), use_prefilter) for i, finding in enumerate(findings)]
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_index = {
            executor.submit(classify_single, task): task[0] 
            for task in tasks
        }
        
        for future in as_completed(future_to_index):
            try:
                index, classified = future.result()
                # Remove internal tracking
                if "_prefiltered" in classified:
                    del classified["_prefiltered"]
                results[index] = classified
            except Exception as e:
                index = future_to_index[future]
                results[index] = findings[index].copy()
                results[index]["_llm_label"] = "TRUE_POSITIVE"
                results[index]["_llm_confidence"] = 0.5
                results[index]["_llm_explanation"] = f"Error: {str(e)[:50]}"
    
    return results


# =============================================================================
# ENTRY POINT
# =============================================================================

if __name__ == "__main__":
    import sys
    
    # Check for --sequential flag
    sequential_mode = "--sequential" in sys.argv
    
    if sequential_mode:
        print("🐢 Running in SEQUENTIAL mode (use for debugging)\n")
        process_findings_sequential(
            input_file="scanner_findings.jsonl",
            output_file="classified_findings.jsonl",
            use_prefilter=True
        )
    else:
        print("🚀 Running in PARALLEL mode (10 concurrent workers)\n")
        process_findings_parallel(
            input_file="scanner_findings.jsonl",
            output_file="classified_findings.jsonl",
            use_prefilter=True,
            max_workers=MAX_WORKERS
        )