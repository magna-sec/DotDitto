"""
DotDitto — session_store.py
In-memory session, disk persistence, password matching, and filtering.
"""
import json
import os
from datetime import datetime

SESSION_FILE = "session.json"

# MD4("") — the NT hash of an empty password. Shows up for accounts with a
# literally blank password, and is also what AD stores for many disabled
# accounts. Treated as "cracked" without needing a pot file entry.
BLANK_NT_HASH = "31d6cfe0d16ae931b73c59d7e0c089c0"

# ---------------------------------------------------------------------------
# In-memory session
# ---------------------------------------------------------------------------

session: dict = {
    "metadata": {
        "created": None,
        "updated": None,
        "dump_sources": [],
        "pot_sources": [],
    },
    "users": [],
    "pot_hashes": {},
    "tier0_users": [],    # list of lowercase "user@domain" strings
    "user_comments": {},  # keyed by "domain/username" (lowercase)
}


# ---------------------------------------------------------------------------
# Session persistence
# ---------------------------------------------------------------------------

def save_session() -> None:
    session["metadata"]["updated"] = datetime.now().isoformat()
    # Write to a temp file in the same directory, then atomically replace the
    # target. A crash mid-write leaves the previous good session.json intact
    # instead of a truncated/corrupt file holding the whole engagement.
    tmp = f"{SESSION_FILE}.tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(session, fh, indent=2, ensure_ascii=False)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, SESSION_FILE)
    except Exception as exc:
        print(f"[warn] could not save session: {exc}")
        try:
            if os.path.exists(tmp):
                os.remove(tmp)
        except OSError:
            pass


def load_session_file() -> None:
    if not os.path.exists(SESSION_FILE):
        return
    try:
        with open(SESSION_FILE, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        if "users" in data:
            session.update(data)
            # Ensure fields added after initial save exist on every user object
            session.setdefault("tier0_users", [])
            session.setdefault("user_comments", {})
            for u in session["users"]:
                u.setdefault("aes256", None)
                u.setdefault("aes128", None)
                u.setdefault("des", None)
                u.setdefault("dump_source", "")
            apply_passwords()
            n_users = len([u for u in session["users"] if not u.get("is_history") and not u.get("is_machine")])
            n_pot = len(session.get("pot_hashes", {}))
            print(f"[info] loaded session: {n_users} user accounts, {n_pot} pot hashes")
    except Exception as exc:
        print(f"[warn] could not load session: {exc}")


def clear_session() -> None:
    """Wipe all session data in-place (avoids breaking imported references)."""
    session.clear()
    session.update(
        {
            "metadata": {
                "created": None,
                "updated": None,
                "dump_sources": [],
                "pot_sources": [],
            },
            "users": [],
            "pot_hashes": {},
            "tier0_users": [],
            "user_comments": {},
        }
    )
    save_session()


def replace_session(data: dict) -> None:
    """Replace session data in-place from an imported dict."""
    session.clear()
    session.update(data)
    session.setdefault("pot_hashes", {})
    session.setdefault("tier0_users", [])
    session.setdefault("user_comments", {})
    session.setdefault(
        "metadata",
        {"created": None, "updated": None, "dump_sources": [], "pot_sources": []},
    )
    # Ensure Kerberos and source fields exist on user objects from older sessions
    for u in session.get("users", []):
        u.setdefault("aes256", None)
        u.setdefault("aes128", None)
        u.setdefault("des", None)
        u.setdefault("dump_source", "")


# ---------------------------------------------------------------------------
# Password matching
# ---------------------------------------------------------------------------

def apply_passwords() -> None:
    """Match cracked hashes from pot_hashes back to users and compute sharing counts.

    Accounts whose NT hash is BLANK_NT_HASH are always treated as cracked
    (password == "") regardless of whether a pot file covers them — there's
    nothing to crack, the hash already proves the password is blank. They're
    flagged via is_blank so callers can label them instead of displaying an
    empty plaintext, and they stay out of password-reuse counts below since
    "everyone with a blank password" isn't meaningful reuse.
    """
    ph = session["pot_hashes"]

    for user in session["users"]:
        is_blank = user["nt_hash"] == BLANK_NT_HASH
        user["is_blank"] = is_blank
        user["password"] = "" if is_blank else ph.get(user["nt_hash"])

    # Count how many (non-history) user accounts share each plaintext.
    # Blank passwords (falsy "") are naturally excluded here.
    pw_counts: dict[str, int] = {}
    for user in session["users"]:
        if user["password"] and not user["is_history"]:
            pw_counts[user["password"]] = pw_counts.get(user["password"], 0) + 1

    for user in session["users"]:
        user["password_count"] = pw_counts.get(user["password"], 1) if user["password"] else 1


# ---------------------------------------------------------------------------
# Tier-0 helpers
# ---------------------------------------------------------------------------

def _build_tier0_lookup(tier0_list: list) -> set:
    """
    Build a fast lookup set from the tier0 user list.
    For each entry like "bob@hi.local", adds both "bob@hi.local" and "bob@hi"
    so that NTDS users with either the FQDN or NetBIOS domain name match.
    """
    lookup: set = set()
    for entry in tier0_list:
        e = entry.strip().lower()
        if not e or e.startswith('#'):
            continue
        lookup.add(e)
        if '@' in e:
            user_part, domain_part = e.split('@', 1)
            first_label = domain_part.split('.')[0]
            if first_label != domain_part:
                lookup.add(f"{user_part}@{first_label}")
    return lookup


def check_is_tier0(username: str, domain: str, tier0_lookup: set) -> bool:
    if not tier0_lookup:
        return False
    u = username.lower()
    d = domain.lower()
    if f"{u}@{d}" in tier0_lookup:
        return True
    first_label = d.split('.')[0]
    if first_label != d and f"{u}@{first_label}" in tier0_lookup:
        return True
    # match bare username (no domain in tier0 entry)
    if u in tier0_lookup:
        return True
    return False


# ---------------------------------------------------------------------------
# Filtering / sorting
# ---------------------------------------------------------------------------

def get_filtered_users(
    search: str = "",
    search_field: str = "all",
    cracked: str = "all",
    domain: str = "all",
    source: str = "all",
    show_history: bool = False,
    show_machines: bool = True,
    sort_by: str = "username",
    sort_dir: str = "asc",
    exclude_domains: set | None = None,
    tier0_only: bool = False,
) -> list:
    all_users = session["users"]
    tier0_lookup  = _build_tier0_lookup(session.get("tier0_users", []))
    comment_map   = session.get("user_comments", {})

    # Separate current accounts from history entries
    history_map: dict[tuple, list] = {}
    current: list = []

    for u in all_users:
        if u["is_history"]:
            key = (u["domain"].lower(), u["base_username"].lower())
            history_map.setdefault(key, []).append(u)
        else:
            current.append(u)

    # Sort history ascending by index: hist_0 = previous, hist_N = oldest
    for entries in history_map.values():
        entries.sort(key=lambda x: x["hist_index"])

    s_lower = search.lower() if search else ""

    def passes(u: dict, check_cracked: bool = True) -> bool:
        if u["is_machine"] and not show_machines:
            return False
        if domain != "all" and u["domain"] != domain:
            return False
        if source != "all" and u.get("dump_source", "") != source:
            return False
        if exclude_domains and u["domain"] in exclude_domains:
            return False
        if check_cracked:
            # "cracked" = real recovered password (excludes blank/disabled);
            # "uncracked" = no password at all (blanks have password == "" so
            # they're excluded here too); "blank" = blank/disabled only.
            if cracked == "cracked" and (u["password"] is None or u.get("is_blank")):
                return False
            if cracked == "uncracked" and u["password"] is not None:
                return False
            if cracked == "blank" and not u.get("is_blank"):
                return False
        if tier0_only and not check_is_tier0(u["username"], u["domain"], tier0_lookup):
            return False
        if s_lower:
            if search_field == "username":
                match = s_lower in u["username"].lower()
            elif search_field == "domain":
                match = s_lower in u["domain"].lower()
            elif search_field == "hash":
                match = s_lower in u["nt_hash"]
            elif search_field == "password":
                match = u["password"] is not None and s_lower in u["password"].lower()
            else:
                match = (
                    s_lower in u["username"].lower()
                    or s_lower in u["domain"].lower()
                    or s_lower in u["nt_hash"]
                    or (u["password"] is not None and s_lower in u["password"].lower())
                )
            if not match:
                return False
        return True

    filtered = [u for u in current if passes(u)]

    # Sort
    reverse = sort_dir == "desc"
    _sort_keys = {
        "username": lambda u: u["username"].lower(),
        "domain":   lambda u: u["domain"].lower(),
        "rid":      lambda u: int(u["rid"]) if u["rid"].isdigit() else 0,
        "nt_hash":  lambda u: u["nt_hash"],
        "password": lambda u: (u["password"] or "").lower(),
        "pw_len":   lambda u: len(u["password"]) if u["password"] is not None else -1,
    }
    if sort_by in _sort_keys:
        filtered.sort(key=_sort_keys[sort_by], reverse=reverse)

    # Always use shallow copies so we never mutate session objects.
    result: list = []
    for u in filtered:
        u_out = dict(u)
        if show_history:
            key = (u["domain"].lower(), u["username"].lower())
            u_out["history"] = history_map.get(key, [])
        else:
            u_out["history"] = []
        u_out["is_tier0"] = check_is_tier0(u["username"], u["domain"], tier0_lookup)
        ck = f"{u['domain'].lower()}/{u['username'].lower()}"
        u_out["comment"] = comment_map.get(ck, "")
        result.append(u_out)

    return result
