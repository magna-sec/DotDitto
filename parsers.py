"""
DotDitto — parsers.py
Parses impacket secretsdump output and hashcat pot files.
"""
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
