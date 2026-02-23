# ·· DotDitto ··
### NTDS Dump Analyzer

> A locally-hosted Flask web application for analysing Active Directory credential dumps produced by impacket's `secretsdump` tool. Visualise cracked passwords, password history, Kerberos keys, and password patterns — fully offline, nothing leaves your machine.

---

## Features

- **NTDS dump ingestion** — file upload or paste; supports secretsdump `-history` output
- **Hashcat pot file support** — load one or more pot files (`HASH:plain` or `$NT$HASH:plain`)
- **Password history timeline** — per-account modal showing current → previous passwords (most recent first)
- **Shared password detection** — highlights accounts sharing the same plaintext
- **Three-tab layout**
  - **Overview** — stats strip, top passwords chart, sortable/filterable user table
  - **All Hashes** — per-user NT (RC4), AES-256, AES-128, and DES Kerberos keys with one-click copy
  - **Mask Analysis** — character-class breakdown, length distribution, and top hashcat mask patterns
- **Wordlist export** — export all unique cracked passwords as a plain-text wordlist (`.txt`)
- **CSV / JSON export** — export filtered table as CSV or full session as JSON
- **Copy uncracked hashes** — one-click copy of all uncracked NT hashes for hashcat
- **Session persistence** — auto-saves to `session.json` (excluded from git)
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

Drag and drop the output file onto the **secretsdump Output** zone, or click **Paste text**.

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

## Exporting

| Action | Description |
|--------|-------------|
| **Export Wordlist** | All unique cracked passwords, one per line (`.txt`) |
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

## File Structure

```
DotDitto/
├── app.py            — Entry point; starts the server
├── routes.py         — All API routes (Flask Blueprint)
├── session_store.py  — In-memory session, persistence, filtering
├── parsers.py        — secretsdump + pot file parsers
├── analysis.py       — Hashcat mask analysis helpers
├── requirements.txt  — Python dependencies
├── templates/
│   └── index.html    — Single-page frontend
├── .gitignore        — Excludes session.json, venv/, etc.
└── README.md
```

---

## Requirements

- Python 3.9+
- Flask 3.x

---

## Mask Analysis

The **Mask Analysis** tab shows:

- Character-class presence rates (uppercase, lowercase, digits, special)
- Password length distribution chart
- Top 30 hashcat mask patterns ranked by frequency with example passwords

Export masks for cracking:

```bash
hashcat -m 1000 hashes.txt -a 3 ntds_masks.hcmask
```

---

## Security Notes

DotDitto is intended for **authorised penetration testing, red team engagements, and defensive security work only**.

- Binds to `127.0.0.1` — not accessible from other hosts
- No authentication — run in a trusted, isolated environment
- `session.json` stores hashes in plaintext; excluded from git via `.gitignore`
- No data is ever sent to external services

Only use DotDitto against systems you have explicit written permission to assess.
