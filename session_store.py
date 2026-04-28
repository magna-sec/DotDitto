"""
DotDitto — session_store.py
In-memory session, disk persistence, password matching, and filtering.
"""
import json
import os
from datetime import datetime

SESSION_FILE = "session.json"

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
}


# ---------------------------------------------------------------------------
# Session persistence
# ---------------------------------------------------------------------------

def save_session() -> None:
    session["metadata"]["updated"] = datetime.now().isoformat()
    try:
        with open(SESSION_FILE, "w", encoding="utf-8") as fh:
            json.dump(session, fh, indent=2, ensure_ascii=False)
    except Exception as exc:
        print(f"[warn] could not save session: {exc}")


def load_session_file() -> None:
    if not os.path.exists(SESSION_FILE):
        return
    try:
        with open(SESSION_FILE, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        if "users" in data:
            session.update(data)
            # Ensure fields added after initial save exist on every user object
            for u in session["users"]:
                u.setdefault("aes256", None)
                u.setdefault("aes128", None)
                u.setdefault("des", None)
                u.setdefault("dump_source", "")
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
        }
    )
    save_session()


def replace_session(data: dict) -> None:
    """Replace session data in-place from an imported dict."""
    session.clear()
    session.update(data)
    session.setdefault("pot_hashes", {})
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
    """Match cracked hashes from pot_hashes back to users and compute sharing counts."""
    ph = session["pot_hashes"]

    for user in session["users"]:
        user["password"] = ph.get(user["nt_hash"])

    # Count how many (non-history) user accounts share each plaintext
    pw_counts: dict[str, int] = {}
    for user in session["users"]:
        if user["password"] and not user["is_history"]:
            pw_counts[user["password"]] = pw_counts.get(user["password"], 0) + 1

    for user in session["users"]:
        user["password_count"] = pw_counts.get(user["password"], 1) if user["password"] else 1


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
) -> list:
    all_users = session["users"]

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
            if cracked == "cracked" and not u["password"]:
                return False
            if cracked == "uncracked" and u["password"]:
                return False
        if s_lower:
            if search_field == "username":
                match = s_lower in u["username"].lower()
            elif search_field == "domain":
                match = s_lower in u["domain"].lower()
            elif search_field == "hash":
                match = s_lower in u["nt_hash"]
            elif search_field == "password":
                match = bool(u["password"]) and s_lower in u["password"].lower()
            else:
                match = (
                    s_lower in u["username"].lower()
                    or s_lower in u["domain"].lower()
                    or s_lower in u["nt_hash"]
                    or (u["password"] and s_lower in u["password"].lower())
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
        result.append(u_out)

    return result
