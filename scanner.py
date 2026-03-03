import re
import os
import sys
import json

# ====================================================================
# IMPROVED REGEX RULE SET - Catches more real secrets
# ====================================================================
RULES = { 
    # 1. Generic Patterns (Loosened to catch more)
    "generic_password_secret_expanded": re.compile(
        r"""(?i)(?:prod(?:uction)?|live|admin)?[_]?(?:db_)?(?:password|passwd|pwd|pass|secret|secret_key|api_secret|app_secret)[_]?(?:key)?\s*=\s*(?:"|\\")[^"\\]{6,}(?:"|\\")"""
    ),
    "generic_api_key_assignment": re.compile(
        r'\b(?:api_key|apikey|access_key|token|secret|auth_token|api_secret)\b[^=]*[:=]\s*["\']?([a-zA-Z0-9_\-\.\+]{16,})["\']?', 
        re.IGNORECASE
    ), 
    
    # 2. Security Tokens & Credentials 
    "rsa_private_key": re.compile(r'-----BEGIN RSA PRIVATE KEY-----', re.IGNORECASE), 
    "dsa_private_key": re.compile(r'-----BEGIN DSA PRIVATE KEY-----', re.IGNORECASE), 
    "ec_private_key": re.compile(r'-----BEGIN EC PRIVATE KEY-----', re.IGNORECASE), 
    "pgp_private_key_block": re.compile(r'-----BEGIN PGP PRIVATE KEY BLOCK-----', re.IGNORECASE), 
    "jwt_token": re.compile(r'eyJ[a-zA-Z0-9_\-]+\.eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+'), 
    "jwt_token_partial": re.compile(r'eyJ[a-zA-Z0-9_\-]{10,}\.e[a-zA-Z0-9_\-]*\.[a-zA-Z0-9_\-]+'),
    "bearer_jwt": re.compile(r'Bearer\s+[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+', re.IGNORECASE), 
    "basic_auth_header": re.compile(r'(?:Basic|Authorization:\s*Basic)\s+(?:[a-zA-Z0-9+\/]{4})*(?:[a-zA-Z0-9+\/]{2}==|[a-zA-Z0-9+\/]{3}=)?', re.IGNORECASE), 
    "bearer_token_header": re.compile(r'(?:bearer|Bearer)\s+[a-zA-Z0-9_\-\.=:_\+\/]{16,}', re.IGNORECASE), 
    "api_key_header": re.compile(r'(?:X-Api-Key|Api-Key|Authorization)\s*[:]\s*[a-zA-Z0-9_\-]{16,}', re.IGNORECASE), 
    
    # 3. Specific Provider Keys - FIXED: Use re.compile() for all
    "google_api_key": re.compile(r'AIzaSy[A-Za-z0-9_-]{32,35}'),
    "google_captcha_key": re.compile(r'6L[A-Za-z0-9_-]{36,}'),
    "google_oauth_token": re.compile(r'ya29\.[0-9A-Za-z_\-]{10,}', re.IGNORECASE), 
    "google_client_secret": re.compile(r'GOCSPX-[a-zA-Z0-9_\-]{20,}', re.IGNORECASE),
    "google_client_id": re.compile(r'[0-9]{10,}-[a-zA-Z0-9]+\.apps\.googleusercontent\.com', re.IGNORECASE),
    
    "aws_access_key_id": re.compile(r'A[SK]IA[0-9A-Z]{16}'),
    "aws_secret_access_key": re.compile(r'(?:AWS_SECRET_ACCESS_KEY|aws_secret_access_key)[^=]*[:=]\s*["\']?([a-zA-Z0-9/+=]{40})["\']?', re.IGNORECASE),
    "aws_mws_token": re.compile(r'amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', re.IGNORECASE), 
    "aws_mws_token_alpha": re.compile(r'amzn\.mws\.[0-9a-z]{4,8}-[0-9a-z]{2,4}-[0-9a-z]{2,4}-[0-9a-z]{2,4}-[0-9a-z]{8,12}', re.IGNORECASE), 
    
    "facebook_token": re.compile(r'EAACEdEose0cBA[0-9A-Za-z]+', re.IGNORECASE), 
    
    "mailgun_api": re.compile(r'key-[a-zA-Z0-9]{32}', re.IGNORECASE),
    
    "twilio_api": re.compile(r'SK[0-9a-zA-Z]{32}'),
    "twilio_sid": re.compile(r'AC[a-zA-Z0-9_\-]{32}'),
    
    "stripe_api": re.compile(r'sk_live_[0-9a-zA-Z]{20,}'),
    "stripe_api_standalone": re.compile(r'\bsk_live_[0-9a-zA-Z_]{16,}\b'),
    
    # 4. NEW PROVIDER PATTERNS
    "github_token": re.compile(r'gh[pous]_[a-zA-Z0-9]{36,}', re.IGNORECASE),
    "github_token_classic": re.compile(r'github_pat_[a-zA-Z0-9_]{20,}', re.IGNORECASE),
    
    "slack_token": re.compile(r'xox[baprs]-[0-9]{10,}-[0-9a-zA-Z\-]+', re.IGNORECASE),
    
    "discord_webhook": re.compile(r'https://discord(?:app)?\.com/api/webhooks/[0-9]+/[a-zA-Z0-9_\-]+', re.IGNORECASE),
    
    # FIXED: Converted from dict to re.compile()
    "sendgrid_api": re.compile(r'SG\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{20,}'),
    
    "gitlab_token": re.compile(r'glpat-[a-zA-Z0-9_\-]{20,}', re.IGNORECASE),
    
    "heroku_api_key": re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', re.IGNORECASE),
    
    "firebase_key": re.compile(r'AAAA[a-zA-Z0-9_\-]{7,}:[a-zA-Z0-9_\-]{20,}', re.IGNORECASE),
    "firebase_key_assignment": re.compile(r'firebase[_]?(?:server)?[_]?key[^=]*[:=]\s*["\']?([a-zA-Z0-9_\-:]{30,})["\']?', re.IGNORECASE),
    
    "square_token": re.compile(r'sq0atp-[a-zA-Z0-9_\-]{20,}', re.IGNORECASE),
    
    "mailchimp_api": re.compile(r'[a-f0-9]{32}-us[0-9]{1,2}', re.IGNORECASE),
    "mailchimp_api_assignment": re.compile(r'mailchimp[_]?api[_]?key[^=]*[:=]\s*["\']?([a-zA-Z0-9\-]{20,})["\']?', re.IGNORECASE),
    
    # 5. Connection Strings
    "mongodb_connection": re.compile(r'mongodb(?:\+srv)?://[^:]+:[^@]+@[^\s"\']+', re.IGNORECASE),
    "postgres_connection": re.compile(r'postgres(?:ql)?://[^:]+:[^@]+@[^\s"\']+', re.IGNORECASE),
    "mysql_connection": re.compile(r'mysql://[^:]+:[^@]+@[^\s"\']+', re.IGNORECASE),
    "azure_connection_string": re.compile(r'(?:DefaultEndpointsProtocol|AccountKey)=[^;\s"\']+', re.IGNORECASE),
    
    # 6. URL with secrets
    "url_secret_param": re.compile(r'(?:key|token|password|secret|pwd|access_token)=([a-zA-Z0-9_\-\.\+]{16,})', re.IGNORECASE), 
    
    # 7. Config file patterns
    "config_secret_key": re.compile(r"(?:config|app\.config|settings)\[['\"](?:SECRET_KEY|secret_key)['\"]]\s*=\s*['\"]([^'\"]{16,})['\"]", re.IGNORECASE),
    "env_secret": re.compile(r"(?:process\.env|os\.environ)\[['\"]?(?:DB_PASSWORD|SECRET_KEY|API_KEY|ACCESS_TOKEN)['\"]?\]\s*=\s*['\"]([^'\"]+)['\"]", re.IGNORECASE),
    
    # 8. Generic high-entropy secrets
    "generic_service_token": re.compile(r'\b(?:webhook_url|api_token|auth_key|client_secret|server_key)\b[^=]*[:=]\s*["\']?([a-zA-Z0-9_\-\.\+:\/]{20,})["\']?', re.IGNORECASE),
    "generic_secret_export": re.compile(r'export\s+(?:SECRET_KEY|API_KEY|ACCESS_KEY|AUTH_TOKEN)\s*=\s*["\']?([a-zA-Z0-9_\-\.\+]{16,})["\']?', re.IGNORECASE),
    
    # 9. Algolia 
    "algolia_api": re.compile(r'(?:algolia[_]?api[_]?key|ALGOLIA_API_KEY)[^=]*[:=]\s*["\']?([a-zA-Z0-9]{20,})["\']?', re.IGNORECASE),
    
    # 10. Bitbucket
    "bitbucket_secret": re.compile(r'(?:bitbucket_secret|BITBUCKET_SECRET)[^=]*[:=]\s*["\']?([a-zA-Z0-9]{20,})["\']?', re.IGNORECASE),
    
    # 11. Standalone bearer token
    "standalone_bearer": re.compile(r'["\']?Bearer\s+[a-zA-Z0-9_\-\.]{20,}["\']?', re.IGNORECASE),

    # FIXED: Converted from dict to re.compile()
    "json_api_key": re.compile(
        r"""(?:['"]|\\['"])\s*(?:X-Api-Key|Authorization|api[_-]?key|token)\s*(?:['"]|\\['"])\s*:\s*(?:['"]|\\['"])[A-Za-z0-9_\-+=/.]{16,}(?:['"]|\\['"])""",
        re.IGNORECASE
    ),

    "prod_live_secret_export": re.compile(
        r"""(?i)(?:EXPORT_)?(?:PROD(?:UCTION)?|LIVE)_(?:SECRET|KEY|TOKEN|PASSWORD|API_KEY)\s*=\s*(?:['"]|\\['"])[^'\"\\]{6,}(?:['"]|\\['"])"""
    ),

    "algolia_api_key": re.compile(
        r"""(?i)(?:algolia|ALGOLIA)[_]?(?:prod|api|key)?[_]?(?:api|key)?\s*=\s*(?:"|\\")[A-Za-z0-9]{32}(?:"|\\")"""
    ),

    "mailchimp_api_key": re.compile(
        r"""(?i)(?:mailchimp|MAILCHIMP)[_]?(?:prod|api|key)?[_]?(?:api|key)?\s*=\s*(?:"|\\")[A-Za-z0-9]{32}-us\d+(?:"|\\")"""
    ),

    "bitbucket_secret_key": re.compile(
        r"""(?i)(?:bitbucket|BITBUCKET)[_]?(?:prod|live|secret)?[_]?(?:secret|key)?\s*=\s*(?:"|\\")[A-Za-z0-9]{32}(?:"|\\")"""
    ),
}

EXTENSIONS_TO_SCAN = (
    '.py', '.js', '.ts', '.java', '.go', '.php', '.cs', '.rb', '.json', '.sh', '.jsonl',
    '.yaml', '.yml', '.env', '.config', '.xml', '.properties', '.toml', '.ini'
)

LOW_CONF_KEYWORDS = [
    'test', 'example', 'dummy', 'localhost', '127.0.0.1', 'mock', 'fake', 'sample'
]

EXCLUDE_DIRS = ['test', 'tests', 'example', 'examples', 'node_modules', 'vendor', '.git']

HIGH_PRECISION_RULES = {
    "aws_access_key_id", "aws_secret_access_key", "aws_mws_token", "aws_mws_token_alpha",
    "stripe_api", "stripe_api_standalone", "google_api_key", 
    "rsa_private_key", "dsa_private_key", "ec_private_key", "pgp_private_key_block", 
    "twilio_api", "mailgun_api", "google_oauth_token", "google_client_secret", "google_client_id",
    "github_token", "github_token_classic", "slack_token", "discord_webhook",
    "sendgrid_api", "gitlab_token", "firebase_key", "firebase_key_assignment", "square_token",
    "mongodb_connection", "postgres_connection", "mysql_connection", "azure_connection_string",
    "jwt_token", "facebook_token", "google_captcha_key",
    "mailchimp_api", "mailchimp_api_assignment", "algolia_api"
}

def scan_file(filepath):
    findings = []
    ext = os.path.splitext(filepath)[1].lower()

    priority_order = [
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
        "json_api_key", "prod_live_secret_export", "algolia_api_key", "mailchimp_api_key", "bitbucket_secret_key",
        "generic_password_secret_expanded",
        "generic_service_token", "generic_api_key_assignment"
    ]

    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            if ext in ['.json', '.jsonl']:
                try:
                    content = f.read()
                    data = json.loads(content)
                    lines_to_scan = list(data.keys()) if isinstance(data, dict) else content.splitlines()
                except:
                    f.seek(0)
                    lines_to_scan = f.readlines()
            else:
                lines_to_scan = f.readlines()

            for line_no, content_line in enumerate(lines_to_scan, 1):
                clean_content = content_line.strip()
                if not clean_content: 
                    continue

                for rule_name in priority_order:
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
                            "file": filepath,
                            "line": line_no,
                            "rule": rule_name,
                            "snippet": clean_content[:150],
                            "matched_data": m.group(0),
                            "confidence": confidence
                        })
                        break
                            
    except Exception as e:
        sys.stderr.write(f"[ERROR] {filepath}: {e}\n")

    return findings


def scan_directory(root_dir):
    all_findings = []

    for root, dirs, files in os.walk(root_dir, topdown=True):
        dirs[:] = [d for d in dirs if d.lower() not in EXCLUDE_DIRS]

        for file in files:
            ext = os.path.splitext(file)[1].lower()
            if ext not in EXTENSIONS_TO_SCAN:
                continue

            filepath = os.path.join(root, file)
            all_findings.extend(scan_file(filepath))

    return all_findings


def scan_line(line):
    """Scan a single line and return all findings (for testing)"""
    findings = []
    priority_order = list(RULES.keys())
    
    for rule_name in priority_order:
        regex = RULES.get(rule_name)
        if not regex:
            continue
        m = regex.search(line)
        if m:
            is_low = any(k in line.lower() for k in LOW_CONF_KEYWORDS)
            if rule_name in HIGH_PRECISION_RULES:
                confidence = "High_Confidence"
            elif is_low:
                confidence = "Low_Confidence"
            else:
                confidence = "High_Confidence"
                
            findings.append({
                "rule": rule_name,
                "matched_data": m.group(0),
                "confidence": confidence
            })
    return findings


def save_jsonl(findings, output_file):
    if not findings:
        print("✔ No findings.")
        return

    with open(output_file, "w", encoding="utf-8") as f:
        for finding in findings:
            f.write(json.dumps(finding, ensure_ascii=False) + "\n")

    print(f"✔ {len(findings)} findings written to {output_file}")


if __name__ == "__main__":
    INPUT_DIR = "../test_data"
    OUTPUT_JSONL = "scanner_findings.jsonl"

    findings = scan_directory(INPUT_DIR)
    save_jsonl(findings, OUTPUT_JSONL)