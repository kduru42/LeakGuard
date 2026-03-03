"""
SECRET SCANNER - Flask Backend API with STREAMING
==================================================
Uses Server-Sent Events (SSE) to stream classification results
as they complete - gives you BOTH speed AND real-time updates!
"""

from flask import Flask, request, jsonify, Response
from flask_cors import CORS
import json
import os
import queue
import threading
from dotenv import load_dotenv
from concurrent.futures import ThreadPoolExecutor, as_completed

load_dotenv()

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
MAX_WORKERS = 10

if not OPENAI_API_KEY:
    print("⚠️  WARNING: OPENAI_API_KEY not found!")

from scanner import RULES, HIGH_PRECISION_RULES, LOW_CONF_KEYWORDS
from classifier import classify_finding, quick_prefilter, SYSTEM_PROMPT, USER_PROMPT_TEMPLATE

app = Flask(__name__)
CORS(app)

# =============================================================================
# COMPLETE PRIORITY ORDER
# =============================================================================
PRIORITY_ORDER = [
    "github_token", "github_token_classic", "slack_token", "discord_webhook",
    "sendgrid_api", "gitlab_token", "firebase_key", "firebase_key_assignment", 
    "square_token", "mailchimp_api", "mailchimp_api_assignment",
    "algolia_api", "bitbucket_secret",
    "aws_access_key_id", "aws_secret_access_key", "aws_mws_token", "aws_mws_token_alpha",
    "stripe_api", "stripe_api_standalone", 
    "google_api_key", "google_oauth_token", "google_client_secret", "google_client_id", "google_captcha_key",
    "twilio_sid", "twilio_api", "mailgun_api", "facebook_token",
    "rsa_private_key", "pgp_private_key_block", "ec_private_key", "dsa_private_key",
    "mongodb_connection", "postgres_connection", "mysql_connection", "azure_connection_string",
    "jwt_token", "jwt_token_partial", "bearer_jwt", "basic_auth_header", "bearer_token_header", 
    "standalone_bearer", "api_key_header",
    "config_secret_key", "env_secret", "generic_secret_export",
    "url_secret_param", "heroku_api_key",
    "json_api_key", "prod_live_secret_export", 
    "algolia_api_key", "mailchimp_api_key", "bitbucket_secret_key",
    "generic_password_secret_expanded",
    "generic_service_token", "generic_api_key_assignment",
]


def scan_content(content: str) -> list:
    """Scan file content and return findings."""
    findings = []
    content_stripped = content.strip()
    lines_to_scan = []
    
    if content_stripped.startswith('{') and content_stripped.endswith('}'):
        try:
            data = json.loads(content)
            if isinstance(data, dict):
                lines_to_scan = list(data.keys())
        except:
            lines_to_scan = content.split('\n')
    elif content_stripped.startswith('[') and content_stripped.endswith(']'):
        try:
            data = json.loads(content)
            if isinstance(data, list):
                for item in data:
                    if isinstance(item, dict) and 'snippet' in item:
                        lines_to_scan.append(item['snippet'])
                    elif isinstance(item, str):
                        lines_to_scan.append(item)
        except:
            lines_to_scan = content.split('\n')
    else:
        first_line = content_stripped.split('\n')[0].strip()
        if first_line.startswith('{'):
            try:
                for line in content.split('\n'):
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        item = json.loads(line)
                        if isinstance(item, dict) and 'snippet' in item:
                            lines_to_scan.append(item['snippet'])
                    except:
                        lines_to_scan.append(line)
            except:
                lines_to_scan = content.split('\n')
        else:
            lines_to_scan = content.split('\n')
    
    for line_no, line in enumerate(lines_to_scan, 1):
        clean_content = line.strip()
        if not clean_content:
            continue
        
        for rule_name in PRIORITY_ORDER:
            regex = RULES.get(rule_name)
            if not regex:
                continue
            
            m = regex.search(clean_content)
            if m:
                is_low = any(k in clean_content.lower() for k in LOW_CONF_KEYWORDS)
                
                if rule_name in HIGH_PRECISION_RULES:
                    confidence = "High_Confidence"
                elif is_low:
                    confidence = "Low_Confidence"
                else:
                    confidence = "High_Confidence"
                
                findings.append({
                    "line": line_no,
                    "rule": rule_name,
                    "snippet": clean_content[:150],
                    "matched_data": m.group(0)[:100],
                    "confidence": confidence
                })
                break
    
    return findings


def classify_single_finding(finding, client):
    """Classify a single finding using LLM."""
    skip_llm, label, reason = quick_prefilter(finding)
    
    if skip_llm:
        return {
            "finding": finding,
            "llm_label": label,
            "llm_explanation": reason
        }
    
    user_prompt = USER_PROMPT_TEMPLATE.format(
        rule=finding.get("rule", "unknown"),
        snippet=finding.get("snippet", "")[:200],
        matched_data=finding.get("matched_data", "")[:150],
        confidence=finding.get("confidence", "unknown")
    )
    
    try:
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt}
            ],
            temperature=0.1,
            max_tokens=100,
            response_format={"type": "json_object"}
        )
        
        result = json.loads(response.choices[0].message.content)
        llm_label = result.get("label", "TRUE_POSITIVE").upper()
        llm_explanation = result.get("reason", "No explanation")
        
        if "TRUE" in llm_label:
            llm_label = "TRUE_POSITIVE"
        elif "FALSE" in llm_label:
            llm_label = "FALSE_POSITIVE"
        else:
            llm_label = "TRUE_POSITIVE"
            
    except Exception as e:
        llm_label = "TRUE_POSITIVE"
        llm_explanation = f"Error: {str(e)[:50]}"
    
    return {
        "finding": finding,
        "llm_label": llm_label,
        "llm_explanation": llm_explanation
    }


# =============================================================================
# API ENDPOINTS
# =============================================================================

@app.route('/api/health', methods=['GET'])
def health():
    return jsonify({
        "status": "ok", 
        "message": "Secret Scanner API (Streaming)",
        "rules_count": len(RULES),
        "priority_rules": len(PRIORITY_ORDER)
    })


@app.route('/api/scan', methods=['POST'])
def scan():
    """Stage 1: Rule-based scanning."""
    data = request.get_json()
    if not data or 'content' not in data:
        return jsonify({"error": "No content provided"}), 400
    
    findings = scan_content(data['content'])
    return jsonify({"findings": findings, "total": len(findings)})


@app.route('/api/classify', methods=['POST'])
def classify():
    """Single finding classification (for compatibility)."""
    if not OPENAI_API_KEY:
        return jsonify({"error": "OPENAI_API_KEY not configured"}), 500
    
    data = request.get_json()
    if not data or 'finding' not in data:
        return jsonify({"error": "No finding provided"}), 400
    
    from openai import OpenAI
    client = OpenAI(api_key=OPENAI_API_KEY)
    result = classify_single_finding(data['finding'], client)
    
    return jsonify({
        "label": result["llm_label"],
        "reason": result["llm_explanation"]
    })


@app.route('/api/classify-batch', methods=['POST'])
def classify_batch():
    """Batch classification (non-streaming, for compatibility)."""
    if not OPENAI_API_KEY:
        return jsonify({"error": "OPENAI_API_KEY not configured"}), 500
    
    data = request.get_json()
    if not data or 'findings' not in data:
        return jsonify({"error": "No findings provided"}), 400
    
    findings = data['findings']
    if not findings:
        return jsonify({"results": []})
    
    from openai import OpenAI
    client = OpenAI(api_key=OPENAI_API_KEY)
    
    results = [None] * len(findings)
    
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_index = {
            executor.submit(classify_single_finding, f, client): i 
            for i, f in enumerate(findings)
        }
        
        for future in as_completed(future_to_index):
            idx = future_to_index[future]
            try:
                result = future.result()
                results[idx] = {
                    "label": result["llm_label"],
                    "reason": result["llm_explanation"]
                }
            except Exception as e:
                results[idx] = {"label": "TRUE_POSITIVE", "reason": f"Error: {str(e)[:50]}"}
    
    return jsonify({"results": results})


# =============================================================================
# NEW: STREAMING ENDPOINT - Results appear as they complete!
# =============================================================================

@app.route('/api/classify-stream', methods=['POST'])
def classify_stream():
    """
    STREAMING classification - sends results as they complete!
    Uses Server-Sent Events (SSE) format.
    
    Each result is sent immediately when ready, so the UI can
    display findings one-by-one while still processing in parallel.
    """
    if not OPENAI_API_KEY:
        return jsonify({"error": "OPENAI_API_KEY not configured"}), 500
    
    data = request.get_json()
    if not data or 'findings' not in data:
        return jsonify({"error": "No findings provided"}), 400
    
    findings = data['findings']
    if not findings:
        return jsonify({"results": []})
    
    def generate():
        from openai import OpenAI
        client = OpenAI(api_key=OPENAI_API_KEY)
        
        # Queue to collect results from threads
        result_queue = queue.Queue()
        total = len(findings)
        
        def classify_and_queue(index, finding):
            """Classify and put result in queue."""
            try:
                result = classify_single_finding(finding, client)
                result_queue.put({
                    "index": index,
                    "finding": finding,
                    "label": result["llm_label"],
                    "reason": result["llm_explanation"]
                })
            except Exception as e:
                result_queue.put({
                    "index": index,
                    "finding": finding,
                    "label": "TRUE_POSITIVE",
                    "reason": f"Error: {str(e)[:50]}"
                })
        
        # Start all threads
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = [
                executor.submit(classify_and_queue, i, f) 
                for i, f in enumerate(findings)
            ]
            
            # Yield results as they complete
            completed = 0
            while completed < total:
                try:
                    # Wait for next result (with timeout to prevent hanging)
                    result = result_queue.get(timeout=30)
                    completed += 1
                    
                    # Send as SSE event
                    event_data = json.dumps(result)
                    yield f"data: {event_data}\n\n"
                    
                except queue.Empty:
                    # Timeout - send keepalive
                    yield f"data: {json.dumps({'keepalive': True})}\n\n"
            
            # Send completion event
            yield f"data: {json.dumps({'done': True, 'total': total})}\n\n"
    
    return Response(
        generate(),
        mimetype='text/event-stream',
        headers={
            'Cache-Control': 'no-cache',
            'Connection': 'keep-alive',
            'X-Accel-Buffering': 'no'  # Disable nginx buffering
        }
    )


if __name__ == '__main__':
    print("=" * 60)
    print("🔐 Secret Scanner API (STREAMING)")
    print("=" * 60)
    print(f"Rules: {len(RULES)} | Priority: {len(PRIORITY_ORDER)}")
    print("")
    print("Endpoints:")
    print("  GET  /api/health          - Health check")
    print("  POST /api/scan            - Rule-based scan")
    print("  POST /api/classify        - Single finding")
    print("  POST /api/classify-batch  - All at once (fast)")
    print("  POST /api/classify-stream - STREAMING (fast + real-time!)")
    print("=" * 60)
    
    app.run(debug=True, port=5000, threaded=True)