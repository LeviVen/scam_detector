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


## Troubleshooting

- **Frontend can't reach the backend / requests fail:** make sure the backend is running on port `5000` *before* starting the frontend, since the React dev server proxies API calls to it.
- **Port already in use:** stop whatever else is running on `5000` (backend) or `3000` (frontend), or change `PORT` in `backend/.env` (and update the frontend `proxy` setting accordingly).
- **Scan results missing URL/email/phone data:** double check that `backend/.env` still contains valid, non-expired keys for VirusTotal, IPQS, and Veriphone — these providers can rate-limit or revoke free-tier keys over time.
- **Slow scans:** this is expected — VirusTotal URL scans are polled sequentially by design to respect API rate limits, so messages with multiple URLs take longer.


## IMPORTANT
For all the additional files and documents for the project please see "Additional Documents" folder