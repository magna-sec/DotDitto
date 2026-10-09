"""
DotDitto — parsers.py
Parses impacket secretsdump output and hashcat pot files.
"""
import csv
import io
import json
import re

# ---------------------------------------------------------------------------
# Pre-compiled regex patterns
# ---------------------------------------------------------------------------

_HASH_RE = re.compile(r"^[a-fA-F0-9]{32}$|^NO PASSWORD\*+$", re.IGNORECASE)
_HIST_RE = re.compile(r"^(.+?)_history(\d+)$", re.IGNORECASE)
_NT32_RE = re.compile(r"^[a-fA-F0-9]{32}$")
_LM16_RE = re.compile(r"^[a-fA-F0-9]{16}$")
_KERB_RE = re.compile(
    r"^(aes256-cts-hmac-sha1-96|aes128-cts-hmac-sha1-96|des-cbc-md5)$",
    re.IGNORECASE,
)
_HEX_RE = re.compile(r"^[a-fA-F0-9]+$")


# ---------------------------------------------------------------------------
# secretsdump parser
# ---------------------------------------------------------------------------

def parse_secretsdump(text: str, source: str = "") -> list:
    """Parse impacket secretsdump NTDS output into a list of user dicts.

    Handles NTLM lines:  DOMAIN\\user:RID:LMHash:NTHash:::
    And Kerberos lines:  DOMAIN\\user:aes256-cts-hmac-sha1-96:hexhash
                         DOMAIN\\user:aes128-cts-hmac-sha1-96:hexhash
                         DOMAIN\\user:des-cbc-md5:hexhash

    ``source`` is a human-readable label for the ntds.dit this dump came from
    (e.g. the filename).  It is stored on every returned record as
    ``dump_source`` so records from multiple imports can be distinguished.
    """
    users = []
    kerb_map: dict = {}  # (domain_lower, base_username_lower) -> {"aes256": ..., ...}

    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("[") or line.startswith("#"):
            continue

        parts = line.split(":")
        if len(parts) < 3:
            continue

        full_user = parts[0]

        # Split optional domain prefix — normalise to uppercase
        domain, username = "", full_user
        if "\\" in full_user:
            domain, username = full_user.split("\\", 1)
            domain = domain.upper()

        # ── Kerberos hash line (parts[1] is hash type, not numeric RID) ──
        if _KERB_RE.match(parts[1]):
            hash_val = parts[2].strip()
            if _HEX_RE.match(hash_val):
                hist_m = _HIST_RE.match(username)
                base_un = hist_m.group(1) if hist_m else username
                key = (domain.lower(), base_un.lower())
                kerb_map.setdefault(key, {})
                ht = parts[1].lower()
                if "aes256" in ht:
                    kerb_map[key]["aes256"] = hash_val.lower()
                elif "aes128" in ht:
                    kerb_map[key]["aes128"] = hash_val.lower()
                elif "des" in ht:
                    kerb_map[key]["des"] = hash_val.lower()
            continue

        # ── NTLM line: DOMAIN\\user:RID:LMHash:NTHash::: ──
        if len(parts) < 4:
            continue

        rid, lm_hash, nt_hash = parts[1], parts[2], parts[3]

        # RID must be numeric
        if not rid.isdigit():
            continue

        # Both hashes must be valid 32-char hex or the "NO PASSWORD" placeholder
        if not _HASH_RE.match(lm_hash) or not _HASH_RE.match(nt_hash):
            continue

        is_machine = username.endswith("$")

        hist_m = _HIST_RE.match(username)
        is_history = bool(hist_m)
        hist_index = int(hist_m.group(2)) if hist_m else -1
        base_username = hist_m.group(1) if hist_m else username

        users.append(
            {
                "username": username,
                "domain": domain,
                "rid": rid,
                "lm_hash": lm_hash.lower(),
                "nt_hash": nt_hash.lower(),
                "password": None,
                "password_count": 1,
                "is_machine": is_machine,
                "is_history": is_history,
                "hist_index": hist_index,
                "base_username": base_username,
                "aes256": None,
                "aes128": None,
                "des": None,
                "dump_source": source,
            }
        )

    # Attach Kerberos hashes to non-history user entries
    for u in users:
        if not u["is_history"]:
            key = (u["domain"].lower(), u["username"].lower())
            kh = kerb_map.get(key, {})
            if kh:
                u["aes256"] = kh.get("aes256")
                u["aes128"] = kh.get("aes128")
                u["des"] = kh.get("des")

    return users


# ---------------------------------------------------------------------------
# Hashcat pot file parser
# ---------------------------------------------------------------------------

def parse_pot_file(text: str) -> dict:
    """Parse a hashcat pot file.

    Supported formats:
      NTLMHASH:plaintext
      $NT$NTLMHASH:plaintext
    Passwords may contain colons.
    """
    pot: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue

        if line.startswith("$NT$"):
            # $NT$<32-hex>:<password>
            colon = line.find(":", 4)
            if colon == -1:
                continue
            h = line[4:colon].lower()
            pw = line[colon + 1:]
        else:
            # <32-hex>:<password>  — first colon at or after index 32
            colon = line.find(":", 32)
            if colon == -1:
                continue
            possible = line[:colon]
            if not _NT32_RE.match(possible):
                continue
            h = possible.lower()
            pw = line[colon + 1:]

        if _NT32_RE.match(h):
            pot[h] = pw

    return pot


# Straight and smart quote characters — Word/Excel and some exports use the
# curly variants, and they wrap values just the same.
_QUOTE_CHARS = "\"'‘’“”"


def clean_list_entry(line: str) -> str:
    """Unwrap one line of an exported list into a bare value.

    BloodHound, CSV and JSON exports quote their values and often leave the list
    comma on the end — ``"bob@corp.local",`` — none of which is part of the
    account name. Stripped here so the entry matches a dump user.
    """
    line = line.strip().rstrip(",")
    return line.strip(_QUOTE_CHARS + " \t").strip()


def parse_list_entries(text: str) -> list:
    """Parse a one-entry-per-line list (e.g. tier-0 accounts), lowercased.

    Blank lines and ``#`` comments are skipped; every other line is unwrapped by
    :func:`clean_list_entry`. Order is preserved and duplicates are collapsed.
    """
    out: list[str] = []
    seen: set = set()
    for raw in text.splitlines():
        if not raw.strip() or raw.strip().startswith("#"):
            continue
        entry = clean_list_entry(raw).lower()
        if entry and entry not in seen:
            seen.add(entry)
            out.append(entry)
    return out


def parse_known_passwords(text: str) -> list:
    """Parse a list of *known* plaintext passwords — one per line.

    These are passwords obtained outside the cracking effort (found on a network
    share, in a script, in documentation) rather than recovered from a hash, so
    they arrive as bare plaintext with no hash to key off. Blank lines and
    ``#`` comments are skipped; every other line is taken verbatim — trailing
    spaces are legitimate password characters, so only the line ending is
    stripped. Duplicates are collapsed, first occurrence wins.
    """
    out: list[str] = []
    seen: set = set()
    for raw in text.splitlines():
        line = raw.rstrip("\r\n")
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if line not in seen:
            seen.add(line)
            out.append(line)
    return out


def _split_group_cell(cell: str) -> list:
    """Parse a neo4j CSV group cell into a list of group names.

    neo4j Browser exports a list column as a JSON array string —
    ``["DOMAIN ADMINS@CORP.LOCAL","IT STAFF@CORP.LOCAL"]`` — but hand-made
    exports or other tools may use a plain ``;`` / ``,`` separated string, so
    both are handled. Empty cells and literal ``[]`` yield no groups.
    """
    cell = (cell or "").strip()
    if not cell or cell == "[]":
        return []
    # Preferred: a JSON array, exactly what neo4j Browser's CSV export writes.
    if cell.startswith("["):
        try:
            arr = json.loads(cell)
            return [str(g).strip() for g in arr if str(g).strip()]
        except (ValueError, TypeError):
            pass
    # Fallback: a separator-delimited string.
    sep = ";" if ";" in cell else ","
    return [clean_list_entry(g) for g in cell.split(sep) if clean_list_entry(g)]


def _parse_bool(val: str):
    """Parse a neo4j boolean cell. Returns True/False, or None when unknown."""
    v = (val or "").strip().strip(_QUOTE_CHARS + " \t").lower()
    if v in ("true", "1", "yes", "enabled"):
        return True
    if v in ("false", "0", "no", "disabled"):
        return False
    return None


def _normalize_groups(raw) -> list:
    """Normalise a groups value (list, JSON-array string, or delimited string)."""
    if isinstance(raw, (list, tuple)):
        return [str(g).strip() for g in raw if str(g).strip()]
    return _split_group_cell(str(raw) if raw is not None else "")


def _make_bh_record(sam: str, name: str, enabled_raw, groups_raw) -> dict | None:
    """Build one BloodHound record from already-separated fields.

    Shared by the CSV and JSON loaders. Recovers the domain from the principal
    name — users are ``SAM@DNS.DOMAIN``, computers are ``HOST.DNS.DOMAIN`` (no
    ``@``) — and falls back to the name for the SAM when it's missing. Returns
    ``None`` when there's no usable account name.
    """
    sam  = (sam or "").strip().strip(_QUOTE_CHARS + " \t")
    name = (name or "").strip().strip(_QUOTE_CHARS + " \t")

    domain = ""
    if "@" in name:
        local, domain = name.split("@", 1)
        if not sam:
            sam = local
    elif "." in name:
        host, domain = name.split(".", 1)
        if not sam:
            sam = host  # computer short name; NTDS adds the trailing '$'

    if not sam:
        return None

    enabled = enabled_raw if isinstance(enabled_raw, bool) else _parse_bool(enabled_raw)
    return {
        "samaccountname": sam,
        "domain": domain,
        "enabled": enabled,
        "groups": _normalize_groups(groups_raw),
    }


def parse_bloodhound(text: str) -> list:
    """Parse a BloodHound export (neo4j CSV *or* JSON) of users/computers.

    Produced by the *Import BloodHound* Cypher query (run in the neo4j Browser
    and exported with **Export CSV** or **Export JSON**). The format is detected
    automatically; either way the fields are matched by name, case-insensitively,
    so column/key order doesn't matter:

        samaccountname , name , enabled , groups

    ``samaccountname`` is the SAM account name (``jdoe`` / ``WS01$``) that pairs
    with the NTDS username; ``name`` is the BloodHound principal
    (``JDOE@CORP.LOCAL`` / ``WS01.CORP.LOCAL``) used to recover the domain when a
    SAM name is missing. ``groups`` is a list (or JSON-array string) of group
    principals.

    Returns a list of records::

        {"samaccountname": str, "domain": str, "enabled": bool|None,
         "groups": [str, ...]}

    Rows/objects with no usable account name are skipped.
    """
    stripped = text.lstrip("﻿ \t\r\n")
    if stripped[:1] in ("[", "{"):
        try:
            return parse_bloodhound_json(stripped)
        except ValueError:
            pass  # not valid JSON after all — fall through and try CSV
    return parse_bloodhound_csv(text)


def parse_bloodhound_json(text: str) -> list:
    """Parse a neo4j JSON export (an array of row objects, or a {data:[…]} wrapper)."""
    data = json.loads(text)
    if isinstance(data, dict):
        # neo4j/BloodHound exports wrap rows under one of these keys; otherwise
        # treat the object itself as a single row.
        for key in ("data", "records", "rows", "results"):
            if isinstance(data.get(key), list):
                data = data[key]
                break
        else:
            data = [data]
    if not isinstance(data, list):
        return []

    out: list = []
    for row in data:
        if not isinstance(row, dict):
            continue
        low = {str(k).lower(): v for k, v in row.items()}
        rec = _make_bh_record(
            low.get("samaccountname") or low.get("sam") or "",
            low.get("name") or low.get("principal") or "",
            low.get("enabled"),
            low.get("groups") or low.get("memberof") or [],
        )
        if rec:
            out.append(rec)
    return out


def parse_bloodhound_csv(text: str) -> list:
    """Parse a neo4j CSV export of BloodHound users/computers (see parse_bloodhound)."""
    reader = csv.reader(io.StringIO(text))
    rows = list(reader)
    if not rows:
        return []

    header = [h.strip().strip(_QUOTE_CHARS + " \t").lower() for h in rows[0]]

    def col(*names):
        for n in names:
            if n in header:
                return header.index(n)
        return -1

    i_sam    = col("samaccountname", "sam")
    i_name   = col("name", "principal", "n.name")
    i_enab   = col("enabled", "n.enabled")
    i_groups = col("groups", "group", "memberof")

    out: list = []
    for row in rows[1:]:
        if not row or not any(c.strip() for c in row):
            continue

        def cell(idx):
            return row[idx] if 0 <= idx < len(row) else ""

        rec = _make_bh_record(cell(i_sam), cell(i_name), cell(i_enab),
                              cell(i_groups))
        if rec:
            out.append(rec)
    return out


def parse_lm_halves(text: str) -> dict:
    """Parse LM half-hash entries from a hashcat -m 3000 pot file.

    Each LM hash is cracked as two independent 8-byte halves, giving lines:
        <16-hex>:PLAINTEXT_HALF        (optionally $LM$-prefixed)
    Returns a dict of {16-hex-half: uppercase-plaintext-half}. 32-hex NT/full
    lines are ignored here (they're handled by parse_pot_file).
    """
    halves: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith("$LM$"):
            line = line[4:]
        colon = line.find(":")
        if colon == -1:
            continue
        h = line[:colon].lower()
        if _LM16_RE.match(h):
            halves[h] = line[colon + 1:]
    return halves
