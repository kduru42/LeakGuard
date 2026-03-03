# 🔐 LeakGuard — AI-Powered Secrets Scanner

> Scan your source code for leaked credentials and API keys — directly from your browser.

![License](https://img.shields.io/badge/license-GPL--3.0-blue)
![Python](https://img.shields.io/badge/python-3.8%2B-blue)
![Flask](https://img.shields.io/badge/backend-Flask-lightgrey)

---

## What Is This?

**LeakGuard** is a two-stage secrets detection tool that combines fast regex-based scanning with LLM-powered classification to eliminate false positives.

Most secret scanners flood you with noise. This one doesn't.

You upload a file. The backend scans it with 60+ regex rules, then sends each finding to GPT-4o-mini to decide whether it's a real threat or harmless test data. Results stream back into the UI in real time — one by one, as they're classified.

No CLI required. No manual pipeline. Just upload and scan.

---

## How It Works

```
You upload a file via the Web UI
          │
          ▼
┌─────────────────┐
│   scanner.py    │  60+ regex rules fire against each line
└────────┬────────┘
         │  findings list
         ▼
┌─────────────────┐
│  classifier.py  │  Pre-filter + GPT-4o-mini (10 parallel workers)
└────────┬────────┘
         │  TRUE_POSITIVE / FALSE_POSITIVE + explanation
         ▼
┌─────────────────┐
│   server.py     │  Streams results via SSE as each finding completes
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│   index.html    │  Results appear in real time in the chat-style UI
└─────────────────┘
```

---

## Quickstart

### 1. Clone & Install

```bash
git clone https://github.com/kduru42/LeakGuard.git
cd LeakGuard
pip install -r requirements.txt
```

### 2. Set Your API Key

```bash
cp .env.example .env
# Edit .env and add your OpenAI key:
# OPENAI_API_KEY=sk-...
```

### 3. Start the Server

```bash
python server.py
```

### 4. Open the UI

Open `index.html` in your browser, upload a source code file, and click **Scan**.

Results stream in as they're classified — no waiting for the full batch to finish.

---

## Features

- ✅ **Web UI** — drag & drop file upload, no CLI needed
- ✅ **Real-time streaming** — findings appear one by one via Server-Sent Events
- ✅ **60+ detection rules** — AWS, GitHub, Stripe, Slack, Google, Firebase, Twilio, and more
- ✅ **LLM classification** — GPT-4o-mini decides TRUE_POSITIVE vs FALSE_POSITIVE with reasoning
- ✅ **Parallel processing** — 10 concurrent API calls for ~10x speed vs sequential
- ✅ **Smart pre-filter** — skips obvious cases (localhost DBs, all-zero placeholders) without LLM call
- ✅ **Export results** — download findings as `.jsonl`
- ✅ **Benchmark system** — measure accuracy against a labeled ground truth dataset

---

## Supported Secret Types

| Category | Examples |
|---|---|
| Cloud | AWS Access Key, AWS Secret, Azure Connection String |
| Version Control | GitHub Token (classic + fine-grained), GitLab PAT |
| Communication | Slack Token, Discord Webhook |
| Payments | Stripe Live Key, Square Token |
| Email | SendGrid, Mailgun, Mailchimp |
| Google | API Key, OAuth Token, Client Secret, Firebase, reCAPTCHA |
| Databases | MongoDB, PostgreSQL, MySQL connection strings |
| Auth | JWT, Bearer Token, Basic Auth, RSA/EC/PGP Private Keys |
| Generic | Passwords, API key assignments, env var exports, config secrets |

---

## API Endpoints

The Flask backend exposes these endpoints (used internally by the UI):

| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/health` | Health check |
| POST | `/api/scan` | Rule-based scan on raw content |
| POST | `/api/classify` | Classify a single finding |
| POST | `/api/classify-batch` | Classify all findings at once |
| POST | `/api/classify-stream` | **Streaming** — results sent via SSE as ready |

---

## Project Structure

```
LeakGuard/
├── index.html          # Web UI (drag & drop, real-time results)
├── server.py           # Flask API + SSE streaming
├── scanner.py          # 60+ regex rules
├── classifier.py       # LLM classifier (parallel + sequential modes)
├── benchmark.py        # Accuracy measurement against ground truth
├── .env.example        # Environment variable template
├── .gitignore
└── README.md
```

---

## Configuration

| Variable | Default | Description |
|---|---|---|
| `OPENAI_API_KEY` | — | Required. Set in `.env` |
| `MAX_WORKERS` | `10` | Concurrent LLM API calls |

---

## Benchmark (Optional)

If you have a labeled ground truth dataset, you can measure pipeline accuracy:

```bash
python benchmark.py
```

Reports matching accuracy, false positive rate, and missed secrets (false negatives).

---

## How the LLM Classification Works

GPT-4o-mini is prompted to think like a senior security engineer. Key behaviors:

- **Weak passwords are TRUE_POSITIVE** — `password123` in a real config is dangerous, not safe
- **Context matters most** — a valid-looking key in a `test_api_key` variable is likely fake
- **When uncertain, lean TRUE_POSITIVE** — missing a real secret is worse than a false alarm
- **Pre-filter skips the LLM** for obvious cases to reduce cost and latency

---

## License

GPL-3.0 — See [LICENSE](LICENSE) for details.
