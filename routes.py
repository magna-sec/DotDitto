"""
DotDitto — routes.py
All Flask API routes, registered as a Blueprint.
"""
import csv
import io
import json
from collections import defaultdict
from datetime import datetime

from flask import Blueprint, Response, jsonify, request

from analysis import build_word_wordlist, run_analysis
from parsers import parse_pot_file, parse_secretsdump
from session_store import (
    BLANK_NT_HASH,
    apply_passwords,
    clear_session,
    get_filtered_users,
    replace_session,
    save_session,
    session,
)

bp = Blueprint("api", __name__)


def _parse_added_within(raw: str) -> float | None:
    """Parse the 'added_within' query param (hours) into a float, or None.

    Empty/"all"/invalid/non-positive values mean 'no time filter'.
    """
    if not raw or raw == "all":
        return None
    try:
        hours = float(raw)
    except ValueError:
        return None
    return hours if hours > 0 else None


# ---------------------------------------------------------------------------
# Pages
# ---------------------------------------------------------------------------

@bp.route("/")
def index():
    from flask import render_template
    return render_template("index.html")


# ---------------------------------------------------------------------------
# Ingestion — dump
# ---------------------------------------------------------------------------

@bp.route("/api/upload/dump", methods=["POST"])
def upload_dump():
    f = request.files.get("file")
    if not f:
        return jsonify({"error": "No file provided"}), 400

    # Allow caller to supply a custom label (e.g. "DC01") instead of the raw filename
    label = (request.form.get("label") or "").strip()
    source = label if label else f.filename
    text = f.read().decode("utf-8", errors="replace")
    users = parse_secretsdump(text, source=source)
    if not users:
        return jsonify({"error": "No valid secretsdump entries found in file"}), 400

    # Replace any existing entries from this same source, then append new ones
    session["users"] = [u for u in session["users"] if u.get("dump_source") != source]
    session["users"].extend(users)
    if not session["metadata"]["created"]:
        session["metadata"]["created"] = datetime.now().isoformat()
    # Rebuild dump_sources from actual data so it stays in sync
    session["metadata"]["dump_sources"] = sorted({
        u["dump_source"] for u in session["users"] if u.get("dump_source")
    })
    apply_passwords()
    save_session()

    total    = len([u for u in users if not u["is_history"] and not u["is_machine"]])
    machines = len([u for u in users if not u["is_history"] and u["is_machine"]])
    hist     = len([u for u in users if u["is_history"]])
    return jsonify(
        {"success": True, "total": total, "machines": machines, "history": hist,
         "filename": source, "source": source}
    )


@bp.route("/api/paste/dump", methods=["POST"])
def paste_dump():
    data = request.get_json(silent=True) or {}
    text = data.get("text", "")
    if not text.strip():
        return jsonify({"error": "No text provided"}), 400

    source = (data.get("source") or "").strip() or "pasted text"
    users = parse_secretsdump(text, source=source)
    if not users:
        return jsonify({"error": "No valid secretsdump entries found"}), 400

    # Replace any existing entries from this same source, then append new ones
    session["users"] = [u for u in session["users"] if u.get("dump_source") != source]
    session["users"].extend(users)
    if not session["metadata"]["created"]:
        session["metadata"]["created"] = datetime.now().isoformat()
    # Rebuild dump_sources from actual data so it stays in sync
    session["metadata"]["dump_sources"] = sorted({
        u["dump_source"] for u in session["users"] if u.get("dump_source")
    })
    apply_passwords()
    save_session()

    total    = len([u for u in users if not u["is_history"] and not u["is_machine"]])
    machines = len([u for u in users if not u["is_history"] and u["is_machine"]])
    hist     = len([u for u in users if u["is_history"]])
    return jsonify({"success": True, "total": total, "machines": machines, "history": hist,
                    "source": source})


# ---------------------------------------------------------------------------
# Ingestion — pot
# ---------------------------------------------------------------------------

@bp.route("/api/upload/pot", methods=["POST"])
def upload_pot():
    files = request.files.getlist("files")
    if not files or not files[0].filename:
        return jsonify({"error": "No files provided"}), 400

    now = datetime.now().isoformat()
    pot_added = session.setdefault("pot_added", {})
    total_new = 0
    names = []
    for f in files:
        pot = parse_pot_file(f.read().decode("utf-8", errors="replace"))
        # Stamp each genuinely new hash with the time it first entered the pot
        for h in pot:
            if h not in session["pot_hashes"]:
                pot_added[h] = now
        session["pot_hashes"].update(pot)
        total_new += len(pot)
        names.append(f.filename)

    session["metadata"]["pot_sources"] = names
    apply_passwords()
    save_session()
    return jsonify(
        {"success": True, "count": total_new, "total_pot": len(session["pot_hashes"]), "filenames": names}
    )


@bp.route("/api/paste/pot", methods=["POST"])
def paste_pot():
    data = request.get_json(silent=True) or {}
    text = data.get("text", "")
    if not text.strip():
        return jsonify({"error": "No text provided"}), 400

    pot = parse_pot_file(text)
    now = datetime.now().isoformat()
    pot_added = session.setdefault("pot_added", {})
    for h in pot:
        if h not in session["pot_hashes"]:
            pot_added[h] = now
    session["pot_hashes"].update(pot)
    session["metadata"]["pot_sources"] = session["metadata"].get("pot_sources", []) + ["pasted text"]
    apply_passwords()
    save_session()
    return jsonify({"success": True, "count": len(pot), "total_pot": len(session["pot_hashes"])})


# ---------------------------------------------------------------------------
# Data retrieval
# ---------------------------------------------------------------------------

@bp.route("/api/session")
def get_session_info():
    users = session["users"]
    return jsonify(
        {
            "has_dump":      len(users) > 0,
            "has_pot":       len(session["pot_hashes"]) > 0,
            "user_count":    len([u for u in users if not u["is_history"] and not u["is_machine"]]),
            "machine_count": len([u for u in users if not u["is_history"] and u["is_machine"]]),
            "history_count": len([u for u in users if u["is_history"]]),
            "pot_count":     len(session["pot_hashes"]),
            "metadata":      session["metadata"],
        }
    )


@bp.route("/api/users")
def get_users():
    page     = max(1, int(request.args.get("page", 1)))
    per_page = min(500, max(10, int(request.args.get("per_page", 100))))
    exclude_raw = request.args.get("exclude_domains", "")
    excluded = {x.strip() for x in exclude_raw.split(",") if x.strip()}

    users = get_filtered_users(
        search          = request.args.get("search", ""),
        search_field    = request.args.get("search_field", "all"),
        cracked         = request.args.get("cracked", "all"),
        domain          = request.args.get("domain", "all"),
        source          = request.args.get("source", "all"),
        show_history    = request.args.get("show_history", "false") == "true",
        show_machines   = request.args.get("show_machines", "true") == "true",
        sort_by         = request.args.get("sort_by", "username"),
        sort_dir        = request.args.get("sort_dir", "asc"),
        exclude_domains = excluded or None,
        tier0_only      = request.args.get("tier0_only", "false") == "true",
        added_within_hours = _parse_added_within(request.args.get("added_within", "")),
    )

    total  = len(users)
    pages  = max(1, (total + per_page - 1) // per_page)
    start  = (page - 1) * per_page

    # Compute top passwords, cracked count, and blank count from the full
    # filtered result. Blank/disabled accounts are tallied separately — they
    # aren't a cracking win and an empty plaintext isn't a meaningful pattern.
    pw_freq: dict[str, int] = {}
    cracked_count = 0
    blank_count   = 0
    for u in users:
        if u.get("is_history") or u.get("is_machine"):
            continue
        if u.get("is_blank"):
            blank_count += 1
        elif u.get("password") is not None:
            cracked_count += 1
            pw_freq[u["password"]] = pw_freq.get(u["password"], 0) + 1
    top_pw = sorted(pw_freq.items(), key=lambda x: x[1], reverse=True)[:15]

    return jsonify(
        {
            "users":         users[start: start + per_page],
            "total":         total,
            "page":          page,
            "per_page":      per_page,
            "pages":         pages,
            "cracked_count": cracked_count,
            "blank_count":   blank_count,
            "top_passwords": [{"password": p, "count": c} for p, c in top_pw],
        }
    )


@bp.route("/api/stats")
def get_stats():
    domain = request.args.get("domain", "all")
    source = request.args.get("source", "all")
    exclude_raw = request.args.get("exclude_domains", "")
    excluded = {x.strip() for x in exclude_raw.split(",") if x.strip()}

    all_u    = session["users"]
    non_hist = [u for u in all_u if not u["is_history"]]

    def in_scope(u: dict) -> bool:
        if domain != "all" and u["domain"] != domain:
            return False
        if source != "all" and u.get("dump_source", "") != source:
            return False
        if excluded and u["domain"] in excluded:
            return False
        return True

    scoped     = [u for u in non_hist if in_scope(u)]
    # krbtgt never cracks and isn't a real crack target — keep it out of the
    # user-account population that drives the crack rate.
    krbtgt     = [u for u in scoped if u.get("is_krbtgt")]
    user_accts = [u for u in scoped if not u["is_machine"] and not u.get("is_krbtgt")]
    machines   = [u for u in scoped if u["is_machine"]]
    # History count is always global (not filtered)
    hist_entries = [u for u in all_u if u["is_history"]]
    # "cracked" means a real recovered password. Blank/disabled accounts are
    # counted separately so they don't inflate the crack rate.
    blank      = [u for u in user_accts if u.get("is_blank")]
    cracked    = [u for u in user_accts if u["password"] is not None and not u.get("is_blank")]

    pw_freq: dict[str, int] = {}
    for u in cracked:
        pw_freq[u["password"]] = pw_freq.get(u["password"], 0) + 1
    top_pw = sorted(pw_freq.items(), key=lambda x: x[1], reverse=True)[:15]

    # Domain/source dropdowns always show all options regardless of current filter.
    # Append "" (accounts with no DOMAIN\ prefix — local/SAM accounts) so they're
    # filterable; the frontend labels it "(no domain)".
    domains = sorted({u["domain"] for u in all_u if u["domain"]})
    if any(not u["domain"] for u in all_u if not u["is_history"]):
        domains.append("")
    sources = sorted({u.get("dump_source", "") for u in all_u if u.get("dump_source")})
    rate    = round(len(cracked) / len(user_accts) * 100, 1) if user_accts else 0.0

    return jsonify(
        {
            "total_users":      len(user_accts),
            "machine_accounts": len(machines),
            "history_entries":  len(hist_entries),
            "cracked":          len(cracked),
            "uncracked":        len(user_accts) - len(cracked) - len(blank),
            "blank":            len(blank),
            "krbtgt":           len(krbtgt),
            "crack_rate":       rate,
            "top_passwords":    [{"password": p, "count": c} for p, c in top_pw],
            "domains":          domains,
            "sources":          sources,
            "metadata":         session["metadata"],
        }
    )


@bp.route("/api/analysis")
def get_analysis():
    """Full password analysis: masks, lengths, char classes, words, prefixes, complexity."""
    domain = request.args.get("domain", "all")
    source = request.args.get("source", "all")
    exclude_raw = request.args.get("exclude_domains", "")
    excluded = {x.strip() for x in exclude_raw.split(",") if x.strip()}

    scope_users = [
        u for u in session["users"]
        if not u["is_history"] and not u["is_machine"] and not u.get("is_krbtgt")
        and (domain == "all" or u["domain"] == domain)
        and (source == "all" or u.get("dump_source", "") == source)
        and (not excluded or u["domain"] not in excluded)
    ]
    # Blank/disabled accounts (password == "") are excluded from both the crack
    # rate and composition analysis — they aren't a cracking win, and an empty
    # plaintext has no mask, length, or character-class pattern to aggregate.
    cracked_pws   = [u["password"] for u in scope_users if u["password"]]
    blank_count   = sum(1 for u in scope_users if u.get("is_blank"))
    total_scope   = len(scope_users)
    crack_rate    = round(len(cracked_pws) / total_scope * 100, 1) if total_scope else 0.0

    result = run_analysis(cracked_pws)
    result["crack_rate"]    = crack_rate
    result["total_scope"]   = total_scope
    result["blank_count"]   = blank_count
    result["cracked_count"] = len(cracked_pws)
    return jsonify(result)


@bp.route("/api/uncracked-hashes")
def uncracked_hashes():
    include_machines = request.args.get("machines", "false") == "true"
    exclude_raw = request.args.get("exclude_domains", "")
    excluded = {x.strip() for x in exclude_raw.split(",") if x.strip()}
    seen:   set  = set()
    hashes: list = []
    for u in session["users"]:
        # password is not None covers blank/disabled accounts too (password
        # == ""), so they stop being resubmitted to the cracking effort once
        # already known-blank.
        if u["is_history"] or u["password"] is not None:
            continue
        if u.get("is_krbtgt"):
            continue  # never a crack target — don't waste a hashcat slot on it
        if u["is_machine"] and not include_machines:
            continue
        if excluded and u["domain"] in excluded:
            continue
        h = u["nt_hash"]
        if len(h) == 32 and h not in seen:
            seen.add(h)
            hashes.append(h)
    return jsonify({"hashes": hashes, "count": len(hashes)})


# ---------------------------------------------------------------------------
# Export / Import
# ---------------------------------------------------------------------------

@bp.route("/api/export/json")
def export_json():
    out = json.dumps(session, indent=2, ensure_ascii=False)
    return Response(
        out,
        mimetype="application/json",
        headers={"Content-Disposition": "attachment; filename=dotditto_session.json"},
    )


@bp.route("/api/import/json", methods=["POST"])
def import_json():
    f = request.files.get("file")
    if not f:
        return jsonify({"error": "No file provided"}), 400
    try:
        data = json.load(f)
    except Exception as exc:
        return jsonify({"error": f"Invalid JSON: {exc}"}), 400

    if "users" not in data:
        return jsonify({"error": "Invalid session file: missing 'users' key"}), 400

    replace_session(data)
    apply_passwords()
    save_session()

    return jsonify(
        {
            "success":    True,
            "user_count": len([u for u in session["users"] if not u["is_history"] and not u["is_machine"]]),
            "pot_count":  len(session["pot_hashes"]),
        }
    )


@bp.route("/api/analysis/domains")
def get_domain_analysis():
    exclude_raw = request.args.get("exclude_domains", "")
    excluded = {x.strip() for x in exclude_raw.split(",") if x.strip()}
    users = session.get("users", [])
    domains = {}
    for u in users:
        if u["is_history"] or u["is_machine"] or u.get("is_krbtgt"):
            continue
        if excluded and u["domain"] in excluded:
            continue
        d = u["domain"]
        if d not in domains:
            domains[d] = {"total": 0, "cracked": 0}
        domains[d]["total"] += 1
        if u["password"] is not None:
            domains[d]["cracked"] += 1
    result = []
    for domain, stats in sorted(domains.items()):
        total = stats["total"]
        cracked = stats["cracked"]
        result.append({
            "domain": domain,
            "total": total,
            "cracked": cracked,
            "crack_rate": round(cracked / total * 100, 1) if total else 0.0
        })
    return jsonify(result)


@bp.route("/api/export/csv")
def export_csv():
    exclude_raw = request.args.get("exclude_domains", "")
    excluded = {x.strip() for x in exclude_raw.split(",") if x.strip()}
    users = get_filtered_users(
        search          = request.args.get("search", ""),
        search_field    = request.args.get("search_field", "all"),
        cracked         = request.args.get("cracked", "all"),
        domain          = request.args.get("domain", "all"),
        source          = request.args.get("source", "all"),
        show_history    = request.args.get("show_history", "false") == "true",
        show_machines   = request.args.get("show_machines", "true") == "true",
        exclude_domains = excluded or None,
        tier0_only      = request.args.get("tier0_only", "false") == "true",
        added_within_hours = _parse_added_within(request.args.get("added_within", "")),
    )
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["Username", "Domain", "RID", "LM Hash", "NT Hash", "Password",
                "Blank/Disabled", "Cracked At", "Shared Count", "Machine", "History", "Hist Index", "Source"])
    for u in users:
        w.writerow(
            [
                u["username"], u["domain"], u["rid"],
                u["lm_hash"], u["nt_hash"],
                "(blank)" if u.get("is_blank") else (u["password"] or ""),
                "Yes" if u.get("is_blank") else "No",
                u.get("cracked_at") or "",
                u["password_count"] if u["password"] is not None else "",
                "Yes" if u["is_machine"] else "No",
                "Yes" if u["is_history"] else "No",
                u["hist_index"] if u["hist_index"] >= 0 else "",
                u.get("dump_source", ""),
            ]
        )
    buf.seek(0)
    return Response(
        buf.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=dotditto_export.csv"},
    )


@bp.route("/api/export/reuse-report")
def export_reuse_report():
    exclude_raw = request.args.get("exclude_domains", "")
    excluded = {x.strip() for x in exclude_raw.split(",") if x.strip()}
    show_passwords = request.args.get("show_passwords", "0") == "1"

    users = [
        u for u in session["users"]
        if not u["is_history"] and not u["is_machine"]
        and (not excluded or u["domain"] not in excluded)
    ]

    hash_groups: dict = defaultdict(list)
    for u in users:
        h = u.get("nt_hash", "")
        if h and len(h) == 32 and h.lower() != BLANK_NT_HASH:
            hash_groups[h].append(u)

    duplicates = {h: g for h, g in hash_groups.items() if len(g) > 1}
    lines: list[str] = []

    if not duplicates:
        lines.append("No duplicate NT hashes found.")
    else:
        sorted_groups = sorted(duplicates.items(), key=lambda x: len(x[1]), reverse=True)
        for nthash, group in sorted_groups:
            passwords = {u["password"] for u in group if u["password"]}
            user_count = len(group)
            short_hash = f"{nthash[:5]}<REDACTED>{nthash[-5:]}"
            if len(passwords) == 1:
                pw = next(iter(passwords))
                pw_part = f": {pw}" if show_passwords else ""
                header = f"Password reused {user_count} times — {short_hash} (Cracked{pw_part})"
            elif passwords:
                header = f"Password reused {user_count} times — {short_hash} (Multiple passwords)"
            else:
                header = f"Password reused {user_count} times — {short_hash} (Not Cracked)"
            lines.append(header)
            lines.append("")
            for u in sorted(group, key=lambda x: x["username"].lower()):
                lines.append(f"  - {u['username']}")
            lines.append("")

    content = "\n".join(lines)
    return Response(
        content,
        mimetype="text/plain",
        headers={"Content-Disposition": "attachment; filename=dotditto_reuse_report.txt"},
    )


@bp.route("/api/export/wordlist")
def export_wordlist():
    """Export all unique cracked passwords as a plain-text wordlist."""
    seen: set   = set()
    words: list = []
    for u in session["users"]:
        if u["password"] and not u["is_history"] and not u["is_machine"]:
            pw = u["password"]
            if pw not in seen:
                seen.add(pw)
                words.append(pw)
    # Sort by frequency (most common first) using pot_hashes reverse lookup
    pw_freq: dict[str, int] = {}
    for u in session["users"]:
        if u["password"] and not u["is_history"] and not u["is_machine"]:
            pw_freq[u["password"]] = pw_freq.get(u["password"], 0) + 1
    words.sort(key=lambda p: pw_freq.get(p, 0), reverse=True)

    content = "\n".join(words)
    return Response(
        content,
        mimetype="text/plain",
        headers={"Content-Disposition": "attachment; filename=dotditto_wordlist.txt"},
    )


@bp.route("/api/export/wordlist/words")
def export_word_wordlist():
    """Export a wordlist of most-used word tokens extracted from cracked passwords."""
    min_count = max(1, int(request.args.get("min_count", 2)))
    cracked_pws = [
        u["password"]
        for u in session["users"]
        if u["password"] and not u["is_history"] and not u["is_machine"]
    ]
    words = build_word_wordlist(cracked_pws, min_count=min_count)
    content = "\n".join(words)
    return Response(
        content,
        mimetype="text/plain",
        headers={"Content-Disposition": "attachment; filename=dotditto_words.txt"},
    )


# ---------------------------------------------------------------------------
# Tier-0 user list
# ---------------------------------------------------------------------------

@bp.route("/api/tier0", methods=["GET"])
def get_tier0():
    users = session.get("tier0_users", [])
    return jsonify({"users": users, "count": len(users)})


@bp.route("/api/tier0/upload", methods=["POST"])
def upload_tier0():
    f = request.files.get("file")
    if not f:
        return jsonify({"error": "No file provided"}), 400
    text = f.read().decode("utf-8", errors="replace")
    users = [
        line.strip().lower()
        for line in text.splitlines()
        if line.strip() and not line.strip().startswith('#')
    ]
    session["tier0_users"] = users
    save_session()
    return jsonify({"success": True, "count": len(users)})


@bp.route("/api/tier0/paste", methods=["POST"])
def paste_tier0():
    data = request.get_json(silent=True) or {}
    text = data.get("text", "")
    if not text.strip():
        return jsonify({"error": "No text provided"}), 400
    users = [
        line.strip().lower()
        for line in text.splitlines()
        if line.strip() and not line.strip().startswith('#')
    ]
    session["tier0_users"] = users
    save_session()
    return jsonify({"success": True, "count": len(users)})


@bp.route("/api/comment", methods=["POST"])
def set_comment():
    data = request.get_json(silent=True) or {}
    key  = data.get("key", "").strip()
    text = data.get("text", "").strip()
    if not key:
        return jsonify({"error": "No key provided"}), 400
    comments = session.setdefault("user_comments", {})
    if text:
        comments[key] = text
    else:
        comments.pop(key, None)
    save_session()
    return jsonify({"success": True})


@bp.route("/api/tier0", methods=["DELETE"])
def clear_tier0():
    session["tier0_users"] = []
    save_session()
    return jsonify({"success": True})


# ---------------------------------------------------------------------------
# Clear
# ---------------------------------------------------------------------------

@bp.route("/api/clear", methods=["POST"])
def clear_all():
    clear_session()
    return jsonify({"success": True})


@bp.route("/api/clear/pot", methods=["POST"])
def clear_pot():
    session["pot_hashes"] = {}
    session["pot_added"] = {}
    session["metadata"]["pot_sources"] = []
    apply_passwords()  # re-derive password/is_blank so blank accounts stay marked cracked
    save_session()
    return jsonify({"success": True})
