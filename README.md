# Scam & Phishing Detector

A web app that analyzes a suspicious message (SMS, email, WhatsApp, etc.) — along with an optional sender email and/or phone number — and returns a verdict (SAFE / SUSPICIOUS / DANGEROUS) with a numeric score, a plain-language summary, and a detailed breakdown of the red flags found.

It combines several signals:
- **AI (LLM) analysis** of the message text for manipulation tactics (urgency, authority claims, prize offers, requests for personal info, etc.)
- **Local heuristics** on any URLs found in the message (suspicious TLDs, brand impersonation, raw IPs, redirect chains, etc.)
- **VirusTotal** scanning of URLs
- **IPQS** reputation checks for the sender email
- **Veriphone** validation for the sender phone number
- **Context-consistency LLM checks** that cross-reference the sender's identity data against what the message claims/asks for

## Tech Stack

- **Backend:** Node.js + Express
- **Frontend:** React (Create React App)
- **External APIs:** Groq (LLM inference), VirusTotal, IPQualityScore (IPQS), Veriphone

## Project Structure

```
.
├── backend/
│   ├── server.js          # Express API — all scanning/analysis logic lives here
│   ├── package.json
│   └── .env                # API keys (included in this repo — see setup below)
│
└── frontend/
    ├── public/
    │   └── index.html
    ├── src/
    │   ├── index.js
    │   ├── App.js                       # Root component — holds scan state, calls the backend
    │   ├── App.css
    │   └── components/
    │       ├── ScanPanel.js             # Input form (message, sender email/phone, no-history toggle)
    │       ├── ScanPanel.css
    │       ├── ResultPanel.js           # Renders the verdict, score, flags, sender cards, URL results
    │       └── ResultPanel.css
    └── package.json
```

## How It Works (Flow)

1. **User submits a scan** from `ScanPanel` — the message text, an optional sender email, an optional sender phone, and a "no prior history" checkbox — which is sent to the backend via `POST /api/scan`.

2. **Phase 1 (parallel):**
   - All URLs found in the message are extracted and their redirects followed to reveal the true destination.
   - If a sender email was provided, it's checked against IPQS.
   - If a sender phone was provided, it's checked against Veriphone.

3. **Phase 2 (parallel):**
   - The message text (with URLs stripped out) is sent to an LLM (via Groq) to score manipulation tactics in the language itself.
   - If email/phone data was collected in Phase 1, two more LLM calls check whether that sender data is *consistent* with what the message claims (e.g. "claims to be your bank" + "sent from a disposable Gmail address" = mismatch).

4. **URL scanning (sequential):** Each URL is submitted to VirusTotal and polled for results (done sequentially to respect API rate limits), combined with the local heuristic URL score.

5. **Aggregation:** All of the above — message score, URL penalties, sender verdicts — are combined into one final score and verdict, which is returned to the frontend.

6. **Result rendering:** `ResultPanel` displays the verdict badge, score, summary, red flags, sender identity cards, per-URL scan results, and a collapsible technical details section.

## Prerequisites

- [Node.js](https://nodejs.org/) (v16 or later recommended) and npm
- No API keys need to be obtained separately — `backend/.env` is already included in this repository with working keys for:
  - [Groq](https://console.groq.com/) — LLM analysis
  - [VirusTotal](https://www.virustotal.com/gui/join-us) — URL scanning
  - [IPQualityScore](https://www.ipqualityscore.com/) — email reputation
  - [Veriphone](https://veriphone.io/) — phone validation

## Setup & Running Locally

### 1. Clone the repository

```bash
git clone <repository-url>
cd <repository-folder>
```

### 2. Backend setup

```bash
cd backend
npm install
npm start
```

This runs the API on `http://localhost:5000` (or use `npm run dev` for auto-restart via nodemon during development).

### 3. Frontend setup

In a separate terminal:

```bash
cd frontend
npm install
npm start
```

This runs the React dev server on `http://localhost:3000` and proxies API requests to the backend on port 5000 (configured via the `proxy` field in `frontend/package.json`).

### 4. Use the app

Open `http://localhost:3000` in your browser, paste a suspicious message (optionally with a sender email/phone), and click **Scan Message**.

## Notes

- This repository (and its `.env` file with live API keys) is intended to stay **private**. If it's ever made public, or forked/shared outside its intended audience, the keys should be revoked/rotated immediately.
- VirusTotal free-tier API keys are rate-limited, which is why URL scans run sequentially with a delay between requests.
