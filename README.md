# ·· DotDitto ··
### NTDS Dump Analyzer

> A locally-hosted Flask web application for analysing Active Directory credential dumps produced by impacket's `secretsdump` tool. Visualise cracked passwords, password history, Kerberos keys, and password patterns — fully offline, nothing leaves your machine.

---

## Features

- **NTDS dump ingestion** — file upload or paste; supports secretsdump `-history` output; each dump can be tagged with a source label (DC hostname) for deduplication and filtering
- **Hashcat pot file support** — load one or more pot files (`HASH:plain` or `$NT$HASH:plain`)
- **Known passwords** — load plaintexts recovered *outside* the cracking effort (network shares, scripts, documentation); matched to accounts by NT hash and shown in blue with a `known` badge so they never read as a crack. Excluded from the crack rate everywhere
- **Machine accounts toggle** — one tick box in the header includes machine (`$`) accounts in every stat, chart, analysis, export and table; off by default
- **Multi-domain sessions** — load dumps from multiple domains simultaneously; filter by domain across all views
- **Domain visibility management** — show/hide individual domains from all stats and charts
- **Domain comparison** — side-by-side crack rate and account stats across any combination of domains
- **Password history timeline** — click the history button (⏱) in the History column to open a per-account modal showing current → previous passwords, oldest to newest
- **Shared password detection** — a `×N` badge beside the NT hash on any account whose password is shared with others; click it to list them. Works on **uncracked** accounts too (identical NT hash ⇒ identical password), with a dedicated **Shared Passwords** analytic on the Analysis tab
- **Password length column** — displays character count for each cracked password; sortable
- **"hist cracked" warning** — yellow badge on rows where the current hash is uncracked but a historical password was cracked
- **Three-tab layout**
  - **Overview** — stats strip, domain comparison, top passwords chart, sortable/filterable user table with copy buttons for hashes and passwords
  - **All Hashes** — per-user NT (RC4), AES-256, AES-128, and DES Kerberos keys with one-click copy
  - **Analysis** — shared-password clusters (works with no pot file loaded), character-class breakdown, password reuse stats, complexity buckets, length distribution, top hashcat mask patterns, top word tokens, and top prefixes
- **Tier-0 user tracking** — load a list of privileged accounts (file, paste, or BloodHound Cypher query); matching rows are flagged with a `T0` badge and a red left border; filter the table to tier-0 accounts only
- **BloodHound import** — load a neo4j CSV/JSON export (users/computers with groups, enabled status, and tier-0 tagging); disabled accounts are badged and dimmed, tier-0 accounts/groups are flagged `T0`, clicking a username shows its group membership, the search bar gains a group-member lookup, and accounts or groups can be tagged (e.g. `privileged`) to filter the table (see [BloodHound Import](#bloodhound-import))
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

### Known passwords

Passwords you already have but never cracked — found in a script on a share, in
a password-manager export, in handover documentation. Drop the file onto the
**Known Passwords** zone (or paste it); multiple files are merged.

One plaintext per line. Blank lines and `#` comments are ignored; everything
else is taken verbatim, including trailing spaces:

```
# \\fs01\it$\build\unattend-notes.txt
Summer2024!
Welcome123
CompanyName1
```

Each entry is NT-hashed locally and matched against the dump, so a hit is
*proof* that account uses that password — but it was never cracked. Matching
accounts show the plaintext in **blue with a `known` badge** instead of the
green cracked styling.

The known list **overrides** a hashcat crack of the same hash: adding a password
here re-marks any account already showing it as *known*, and clears its "Added"
timestamp. That's deliberate — found passwords are routinely pasted into a pot
file so the tooling picks them up, which would otherwise launder them into the
crack rate. Clearing the known list restores them to cracked.

Beyond the styling:

- they are **excluded from the crack rate**, the Cracked count, the top-password
  chart, and all Analysis-tab composition stats (a separate **Known** stat card
  and a `known` count appear once any are matched)
- they are **included** in the wordlist export — they're valid plaintexts for
  this environment
- their hashes are **not** in the uncracked-hash export (the password is known,
  so there's nothing left to crack)
- `Cracked only` / `Known passwords only` in the toolbar filter scopes the table
  to either group; CSV export gains a **Password Origin** column
  (`Cracked` / `Known` / `Blank/Disabled`)

Use **Clear Known** to drop the list; affected accounts revert to uncracked.

---

## Shared Passwords

NT hashes are unsalted, so two accounts with the same NT hash are using the same
password — **whether or not it has been cracked**. That's the one reuse signal
available before you crack anything, and it's usually the most useful finding in
a dump.

**On the Overview and All Hashes tables**, any account whose hash is shared gets
a `×N` badge next to the NT hash — `×14` means 14 accounts in total hold that
password. Click it for the full list (usernames, RIDs, tier-0 / machine badges,
notes, source) plus a **Copy usernames** button for reporting. The badge is
**yellow** when the password is recovered and **red** when it isn't — a red `×40`
is forty accounts you own the moment one crack lands.

**On the Analysis tab**, the **Shared Passwords** card ranks the largest clusters:

| Metric | Meaning |
|---|---|
| Accounts sharing a password | % of accounts whose password is used by at least one other account |
| Distinct shared passwords | how many separate reused passwords exist |
| Largest cluster | the biggest single group |
| Accounts on unrecovered shared passwords | the crack targets with the highest blast radius |

Each row shows the hash, the count, the plaintext (or *not recovered*), and the
first five members — click any row to open the same list. Clusters containing a
tier-0 account are flagged `T0`.

Excluded from all of the above: password-history entries (a user's own former
password isn't reuse) and the empty-password hash (every disabled account carries
it, so it would report the whole disabled estate as one giant cluster). The
counts follow the same scope as everything else — hidden domains and the
machine-account toggle apply, so ticking **Machines** surfaces cloned-image
workstations sharing a machine password.

The **Export Reuse Report** button writes the same groups to a text file, with
the option to redact plaintexts.

---

## Machine Accounts

Machine (`$`) accounts hold random 120-character passwords that never crack, so
they're left out of everything by default. The **Machines** tick box in the
header opts them back into *all* analysis at once:

| Included when ticked |
|---|
| Stats strip, crack rate, and domain comparison |
| Analysis tab (masks, lengths, char classes, per-domain summary) |
| Overview and All Hashes tables |
| Wordlist / word-token / reuse-report exports and **Copy Uncracked Hashes** |

The two **Include machines** boxes in the table toolbars are the same switch —
tick any one and they all follow. The setting is saved to `localStorage`, and
the **User Accounts** stat card relabels itself to **Accounts (incl. machines)**
so a screenshot is never ambiguous about which population a rate refers to.

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

Export quoting is stripped automatically, so you can paste straight out of
BloodHound, a CSV column, or a JSON array without cleaning it up first — all of
these load as `bob@corp.local`:

```
"bob@corp.local"
'bob@corp.local'
"bob@corp.local",
```

Blank lines and `#` comments are ignored, and duplicates are collapsed.

Once loaded, matching accounts are flagged with a red `T0` badge in the Username column. Use the **Tier 0 only** filter in the toolbar to scope the table to privileged accounts.

---

## BloodHound Import

Click **Import BloodHound** in the header to enrich the dump with group
membership and account status pulled from BloodHound/neo4j. The panel carries a
ready-made Cypher query:

```cypher
MATCH (n)
WHERE n:User OR n:Computer
OPTIONAL MATCH (n)-[:MemberOf*1..]->(g:Group)
RETURN n.samaccountname AS samaccountname, n.name AS name,
       n.enabled AS enabled,
       (n:Tag_Tier_Zero OR COALESCE(n.system_tags,'') CONTAINS 'admin_tier_0') AS tier0,
       collect(DISTINCT g.name) AS groups,
       collect(DISTINCT CASE WHEN (g:Tag_Tier_Zero OR COALESCE(g.system_tags,'') CONTAINS 'admin_tier_0') THEN g.name END) AS tier0_groups
```

Run it in the **neo4j Browser**, use its **Export CSV** *or* **Export JSON**
button, and load the file back here (upload or paste) — the format is detected
automatically. Fields are matched by name (`samaccountname`, `name`, `enabled`,
`groups`), so column/key order doesn't matter. Accounts are matched to the dump
by SAM name + domain — the same FQDN/NetBIOS-tolerant matching used for tier-0.

Once loaded:

- accounts that are **disabled** in AD get a grey `disabled` badge and a dimmed
  row (both the Overview and All Hashes tables). Accounts absent from the import
  are left unmarked — unknown, not assumed enabled
- **tier-0** accounts get the red `T0` badge and count toward the **Tier 0 only**
  filter, exactly like the manually-loaded tier-0 list. An account is tier-0 when
  BloodHound tags the node itself tier-zero *or* it's a member of a tier-zero
  group (e.g. Domain Admins); tier-zero groups are badged `T0` in the popup
- **clicking a username** opens a popup listing that account's groups, with a
  **Copy groups** button
- the **search field** dropdown gains **Group member** — search for a group name
  to list every member of it. Groups are searched *only* when this field is
  selected; the default *All fields* search never matches on group membership
- **CSV export** gains **AD Enabled**, **Groups**, and **Group Tags** columns

Use **Clear** in the panel to drop the imported data. It's saved with the
session and restored on reload.

### Tags

Click a username to open the group popup. At the top is a **This account** row,
and each group below has its own **+ tag** box. Type any label — `privileged`,
`bypasses mfa`, `can reset passwords`, whatever is useful for the engagement —
and press Enter to tag either the **account itself** or a **group**; the `×` on a
tag chip removes it. Tags are free-text, a group or account can carry several, and
an autocomplete offers tags already in use so spellings stay consistent.

Tagging the **account** works even for accounts BloodHound never found (so they
have no groups) — useful for flagging something you learned out-of-band.

Every distinct tag then appears in the **user-scope dropdown** (alongside *All
users* and *Tier 0 only*) as **Tag: &lt;name&gt;**. Selecting it scopes the table
to every account that carries that tag directly *or* is a member of any group
carrying it — e.g. tag the handful of groups that lead to Domain Admin as
`privileged`, then filter to everyone who can reach DA. Tagged accounts show the
tag as a badge in the Username column, and tags export in the **Group Tags** CSV
column. Tags are saved with the session.

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
| **Export Wordlist** | All unique recovered passwords — cracked *and* known — one per line (`.txt`) |
| **Export Word Tokens** | Most-common word tokens extracted from cracked passwords (`.txt`) |
| **Export CSV** | Current filtered table as a flat CSV (includes a **Password Origin** column) |
| **Export JSON** | Full session snapshot (dump + pot hashes + known passwords + notes), re-importable via **Import JSON** |
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
- **Shared Passwords** — the largest clusters of accounts sharing one NT hash
  (see [Shared Passwords](#shared-passwords)); the only card that populates
  without a pot file loaded

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
