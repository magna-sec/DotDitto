# ·· DotDitto ··
### NTDS Dump Analyzer

> A locally-hosted Flask web application for analysing Active Directory credential dumps produced by impacket's `secretsdump` tool. Visualise cracked passwords, password history, Kerberos keys, and password patterns — fully offline, nothing leaves your machine.

---

## Features

- **NTDS dump ingestion** — file upload or paste; supports secretsdump `-history` output
- **Hashcat pot file support** — load one or more pot files (`HASH:plain` or `$NT$HASH:plain`)
- **Multi-domain sessions** — load dumps from multiple domains simultaneously; each gets its own tab
- **Domain visibility management** — show/hide individual domains from all stats and charts
- **Domain comparison** — side-by-side crack rate and account stats across any combination of domains
- **Password history timeline** — per-account modal showing current → previous passwords (most recent first)
- **Shared password detection** — highlights accounts sharing the same plaintext
- **Three-tab layout per domain**
  - **Overview** — stats strip, top passwords chart, sortable/filterable user table
  - **All Hashes** — per-user NT (RC4), AES-256, AES-128, and DES Kerberos keys with one-click copy
  - **Analysis** — character-class breakdown, length distribution, top hashcat mask patterns, top word tokens, and top prefixes
- **Overall tab** — aggregate stats and crack rate across all loaded domains
- **Client Mode** — blurs sensitive data for client-facing demos; independently toggle hiding of passwords/hashes and/or usernames
- **Wordlist exports**
  - All unique cracked passwords as a plain-text wordlist (`.txt`)
  - Most-common word tokens extracted from cracked passwords
- **CSV / JSON export** — export filtered table as CSV or full session as JSON
- **Copy uncracked hashes** — one-click copy of all uncracked NT hashes for hashcat
- **Session persistence** — auto-saves each domain to `sessions/<domain>.json` (excluded from git)
- **Fully offline** — binds to `127.0.0.1:5000` only; no external requests, no telemetry

---

## Quick Start

```bash
# 1. Create and activate a virtual environment
python -m venv venv

# Windows
venv\Scripts\activate
# Linux / macOS
source venv/bin/activate

# 2. Install dependencies
pip install -r requirements.txt

# 3. Run DotDitto
python app.py
```

Open **http://localhost:5000** in your browser.

---

## Loading Data

### secretsdump output

Run secretsdump against an NTDS.dit (with history if desired):

```bash
# Offline
secretsdump.py -ntds ntds.dit -system SYSTEM -hashes lmhash:nthash LOCAL -history

# Live DC
secretsdump.py DOMAIN/user:pass@dc.corp.local -history
```

Drag and drop the output file onto the **secretsdump Output** zone, or click **Paste text**. A source label (e.g. DC hostname) can be optionally set before uploading — this appears in the Source column and is used for deduplication if you reload the same DC.

Supported formats parsed automatically:

```
# NTLM
DOMAIN\username:RID:LMHash:NTHash:::
DOMAIN\username_history0:RID:LMHash:NTHash:::

# Kerberos
DOMAIN\username:aes256-cts-hmac-sha1-96:<hex>
DOMAIN\username:aes128-cts-hmac-sha1-96:<hex>
DOMAIN\username:des-cbc-md5:<hex>
```

### Hashcat pot file

Run hashcat against the NT hashes, then load the pot file:

```bash
hashcat -m 1000 hashes.txt wordlist.txt -o cracked.pot
```

Load `cracked.pot` onto the **Hashcat Pot File(s)** zone. Multiple pot files can be loaded simultaneously.

Supported pot formats:

```
8846f7eaee8fb117ad06bdd830b7586c:Password1
$NT$8846f7eaee8fb117ad06bdd830b7586c:Password1
```

---

## Multi-Domain Support

DotDitto supports loading dumps from multiple domains in a single session. Each domain gets its own tab. Domains are inferred automatically from the `DOMAIN\username` format in the dump.

- The **Overall** tab shows aggregate stats across all loaded domains
- **Domains ▾** in the header lets you hide specific domains from all stats and charts (useful for excluding machine-account-heavy domains from analysis)
- The **Domain Comparison** panel (Overview tab, appears when ≥ 2 domains are loaded) shows crack rates and account counts side-by-side for any selected domains

Sessions are persisted to `sessions/<domain>.json` and reloaded automatically on start.

---

## Exporting

| Action | Description |
|--------|-------------|
| **Export Wordlist** | All unique cracked passwords, one per line (`.txt`) |
| **Export Word Tokens** | Most-common word tokens extracted from cracked passwords (`.txt`) |
| **Export CSV** | Current filtered table as a flat CSV |
| **Export JSON** | Full session snapshot (dump + pot hashes), re-importable |
| **Export .hcmask** | Top mask patterns ready for `hashcat -a 3` |
| **Copy Uncracked Hashes** | Unique uncracked NT hashes to clipboard |

---

## Password History

Click any row showing a history badge to open the timeline modal. Entries are displayed most-recent first:

```
  ● Current password
  │
  ○ Previous          (history index 0)
  ○ 2 changes ago     (history index 1)
  ○ Oldest            (history index N)
```

---

## Client Mode

Click **Client Mode** in the header to enter a client-facing view. Use the **▾** chevron to configure what is hidden:

| Option | What it blurs |
|--------|--------------|
| **Passwords & hashes** | All cracked passwords, NT/AES/DES hashes, mask examples, history values |
| **Usernames** | All username cells across the Overview and All Hashes tables, history modal title |

Both options can be toggled independently. Preferences are saved to `localStorage` and persist between sessions.

---

## Mask Analysis

The **Analysis** tab shows:

- Character-class presence rates (uppercase, lowercase, digits, special)
- Password length distribution chart
- Top 30 hashcat mask patterns ranked by frequency with example passwords
- Top word tokens found in cracked passwords
- Top common prefixes

Export masks for cracking:

```bash
hashcat -m 1000 hashes.txt -a 3 ntds_masks.hcmask
```

---

## File Structure

```
DotDitto/
├── app.py            — Entry point; starts the server, loads saved sessions
├── routes.py         — All API routes (Flask Blueprint)
├── session_store.py  — Multi-domain in-memory sessions, persistence, filtering
├── parsers.py        — secretsdump + pot file parsers
├── analysis.py       — Hashcat mask analysis helpers
├── requirements.txt  — Python dependencies
├── templates/
│   └── index.html    — Single-page frontend
├── sessions/         — Per-domain session files (gitignored)
├── .gitignore        — Excludes sessions/, venv/, etc.
└── README.md
```

---

## Requirements

- Python 3.9+
- Flask 3.x

---

## Security Notes

DotDitto is intended for **authorised penetration testing, red team engagements, and defensive security work only**.

- Binds to `127.0.0.1` — not accessible from other hosts
- No authentication — run in a trusted, isolated environment
- `sessions/<domain>.json` stores hashes in plaintext; excluded from git via `.gitignore`
- No data is ever sent to external services

Only use DotDitto against systems you have explicit written permission to assess.
