# ·· DotDitto ··
### NTDS Dump Analyzer

> A locally-hosted Flask web application for analysing Active Directory credential dumps produced by impacket's `secretsdump` tool. Visualise cracked passwords, password history, Kerberos keys, and password patterns — fully offline, nothing leaves your machine.

---

## Features

- **NTDS dump ingestion** — file upload or paste; supports secretsdump `-history` output; each dump can be tagged with a source label (DC hostname) for deduplication and filtering
- **Hashcat pot file support** — load one or more pot files (`HASH:plain` or `$NT$HASH:plain`)
- **Multi-domain sessions** — load dumps from multiple domains simultaneously; filter by domain across all views
- **Domain visibility management** — show/hide individual domains from all stats and charts
- **Domain comparison** — side-by-side crack rate and account stats across any combination of domains
- **Password history timeline** — click the history button (⏱) in the History column to open a per-account modal showing current → previous passwords, oldest to newest
- **Shared password detection** — highlights accounts sharing the same plaintext with a reuse badge
- **Password length column** — displays character count for each cracked password; sortable
- **"hist cracked" warning** — yellow badge on rows where the current hash is uncracked but a historical password was cracked
- **Three-tab layout**
  - **Overview** — stats strip, domain comparison, top passwords chart, sortable/filterable user table with copy buttons for hashes and passwords
  - **All Hashes** — per-user NT (RC4), AES-256, AES-128, and DES Kerberos keys with one-click copy
  - **Analysis** — character-class breakdown, password reuse stats, complexity buckets, length distribution, top hashcat mask patterns, top word tokens, and top prefixes
- **Tier-0 user tracking** — load a list of privileged accounts (file, paste, or BloodHound Cypher query); matching rows are flagged with a `T0` badge and a red left border; filter the table to tier-0 accounts only
- **Per-row notes** — click any Notes cell to attach a free-text annotation to an account (e.g. `SNOW Admin`, `Has 2 VDIs`); notes are saved in the session
- **Client Mode** — blurs sensitive data for client-facing screen shares; independently toggle hiding of passwords/hashes and/or usernames
- **Themes** — Dark (default), Professional (clean light), Terminal (green phosphor), Synthwave (retro neon), Classic (Windows 95), Contrast (neon pink/cyan)
- **Brightness slider** — fine-tune display brightness across any theme; setting is saved between sessions
- **Wordlist exports**
  - All unique cracked passwords as a plain-text wordlist (`.txt`)
  - Most-common word tokens extracted from cracked passwords
- **CSV / JSON export** — export filtered table as CSV or full session as JSON (re-importable)
- **Copy uncracked hashes** — one-click copy of all uncracked NT hashes for hashcat
- **Session persistence** — auto-saves the full session to `session.json` (excluded from git)
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

Drag and drop the output file onto the **secretsdump Output** zone, or click **Paste text**. A source label (e.g. DC hostname) can be set before uploading — it appears in the Source column and allows filtering by DC if you load multiple dumps. Loading a second file with a **different** source label adds it alongside existing data; loading one with the **same** label replaces that source's entries.

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

Load `cracked.pot` onto the **Hashcat Pot File(s)** zone. Multiple pot files can be loaded simultaneously; each additional file is **merged** into the existing cracked set — nothing is lost when you add more.

Supported pot formats:

```
8846f7eaee8fb117ad06bdd830b7586c:Password1
$NT$8846f7eaee8fb117ad06bdd830b7586c:Password1
```

---

## Multi-Domain Support

DotDitto supports loading dumps from multiple domains in a single session. Domains are inferred automatically from the `DOMAIN\username` format in the dump.

- The **Overview** tab shows aggregate stats across all domains by default; use the **Domain** filter dropdown to scope any view to a single domain
- **Domains ▾** in the header lets you hide specific domains from all stats and charts (useful for excluding machine-account-heavy domains)
- The **Domain Comparison** panel (Overview tab, appears when ≥ 2 domains are loaded) shows crack rates and account counts side-by-side for any selected domains

All loaded domains share a single session that is persisted to `session.json` and reloaded automatically on start.

---

## Tier-0 Tracking

Click **Tier 0 ▾** in the header to open the Tier-0 panel. Load a list of privileged accounts by:

- **Upload file** — a plain text file, one entry per line
- **Paste text** — paste a list directly
- **BloodHound Cypher query** — the panel includes a ready-made query to copy into BloodHound to export your Tier 0 users

Expected format (one entry per line):

```
administrator@corp.local
krbtgt@corp.local
svc-backup@corp.local
```

Once loaded, matching accounts are flagged with a red `T0` badge in the Username column. Use the **Tier 0 only** filter in the toolbar to scope the table to privileged accounts.

---

## Password History

Click the **⏱ n/m** button in the History column to open the timeline modal for that account. Entries are displayed most-recent first:

```
  ● Current password
  │
  ○ Previous          (history index 0)
  ○ 2 changes ago     (history index 1)
  ○ Oldest            (history index N)
```

Each entry shows the NT hash and cracked password (if available) with a one-click copy button. Reused hashes are flagged with a warning badge.

If a row has no current password cracked but a historical one was, a yellow **hist cracked** badge appears in the Password column.

---

## Notes

Click any cell in the **Notes** column to attach a free-text annotation to an account. Notes are saved as part of the session and exported in JSON exports.

---

## Client Mode

Click **Client Mode** in the header to enter a client-facing view. Use the **▾** chevron to configure what is hidden:

| Option | What it blurs |
|--------|--------------|
| **Passwords & hashes** | All cracked passwords, NT/AES/DES hashes, mask examples, history values |
| **Usernames** | All username cells across the Overview and All Hashes tables, history modal title |

Both options can be toggled independently. Preferences are saved to `localStorage` and persist between sessions.

---

## Themes & Brightness

Click **Theme ▾** in the header to switch themes:

| Theme | Description |
|-------|-------------|
| **Dark** | Default dark mode (GitHub-style) |
| **Professional** | Clean light UI with blue header — suitable for client-facing screens |
| **Terminal** | Green phosphor on black |
| **Synthwave** | Retro 80s neon purple |
| **Classic** | Windows 95 era — raised 3D panels, teal desktop |
| **Contrast** | Neon pink/cyan on near-black navy, glow accents |

Use the **Brightness** slider in the same panel to fine-tune display brightness from 50% to 150%. The selected theme and brightness level are saved to `localStorage`.

---

## Exporting

| Action | Description |
|--------|-------------|
| **Export Wordlist** | All unique cracked passwords, one per line (`.txt`) |
| **Export Word Tokens** | Most-common word tokens extracted from cracked passwords (`.txt`) |
| **Export CSV** | Current filtered table as a flat CSV |
| **Export JSON** | Full session snapshot (dump + pot hashes + notes), re-importable via **Import JSON** |
| **Export .hcmask** | Top mask patterns ready for `hashcat -a 3` |
| **Copy Uncracked Hashes** | Unique uncracked NT hashes to clipboard |

---

## Mask Analysis

The **Analysis** tab shows:

- Character-class presence rates (uppercase, lowercase, digits, special)
- Password reuse stats (unique count, % sharing, max reuse, % containing a year)
- Complexity breakdown by number of character classes used
- Password length distribution chart
- Top 30 hashcat mask patterns ranked by frequency with example passwords
- Top word tokens and common prefixes found in cracked passwords

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
│   └── index.html    — Single-page frontend (~3900 lines)
├── session.json      — Persisted session (created at runtime, gitignored)
├── .gitignore        — Excludes session.json, venv/, etc.
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
- `session.json` stores hashes in plaintext; excluded from git via `.gitignore`
- No data is ever sent to external services

Only use DotDitto against systems you have explicit written permission to assess.
