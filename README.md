# Email Verification Tool

A local tool for cleaning cold-email lead lists before you send. Drop in one or more CSVs and every address is checked live (syntax, MX records, SMTP handshake). You get a verified file back, with a `safe_to_send` flag on every row.

> Built on top of Alex Berman's free desktop email verifier, then extended and hardened (see below). The original footer credit is kept.

## What I added (v3)
- **Accuracy:** duplicate detection, greylisting timeouts, role-based and disposable-address filtering
- **`safe_to_send` column** and a download filter, so you can export only sendable leads
- **Live stats** per file: valid / safe / risky / invalid / catch-all / inferred
- **Reliability:** temp-file cleanup, a cap on greylisting wait, automatic CSV encoding detection, configurable `MAIL_FROM`
- **End-to-end test script** (`test_e2e.py`)

## Features
- Drag-and-drop multiple CSVs, with a progress bar and live log for each one
- Cancel a job mid-run
- Results persist across page refreshes
- Download the verified CSV when it's done

## Tech stack
Python · Flask · dnspython · smtplib · vanilla JavaScript

## Run locally
```bash
python3 -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate
pip install flask flask-cors dnspython chardet

cp .env.example .env              # set MAIL_FROM to a domain you own
set -a && source .env && set +a

python3 verify-app.py             # API on :5050
python3 -m http.server 3000       # in a second terminal
```
Open `http://localhost:3000/index.html` and drop in a CSV.

Run the tests with `python test_e2e.py`.

> **Note:** many ISPs and cloud hosts block outbound port 25, and SMTP checks need it. Run this from a network that allows it.
