"""
DotDitto — routes.py
All Flask API routes, registered as a Blueprint.
"""
import csv
import io
import json
from datetime import datetime

from flask import Blueprint, Response, jsonify, request

from analysis import build_word_wordlist, run_analysis
from parsers import parse_pot_file, parse_secretsdump
from session_store import (
    apply_passwords,
    clear_session,
    get_filtered_users,
    replace_session,
    save_session,
    session,
)

bp = Blueprint("api", __name__)


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

    total_new = 0
    names = []
    for f in files:
        pot = parse_pot_file(f.read().decode("utf-8", errors="replace"))
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
    )

    total  = len(users)
    pages  = max(1, (total + per_page - 1) // per_page)
    start  = (page - 1) * per_page

    return jsonify(
        {
            "users":    users[start: start + per_page],
            "total":    total,
            "page":     page,
            "per_page": per_page,
            "pages":    pages,
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
    user_accts = [u for u in scoped if not u["is_machine"]]
    machines   = [u for u in scoped if u["is_machine"]]
    # History count is always global (not filtered)
    hist_entries = [u for u in all_u if u["is_history"]]
    cracked    = [u for u in user_accts if u["password"]]

    pw_freq: dict[str, int] = {}
    for u in cracked:
        pw_freq[u["password"]] = pw_freq.get(u["password"], 0) + 1
    top_pw = sorted(pw_freq.items(), key=lambda x: x[1], reverse=True)[:15]

    # Domain/source dropdowns always show all options regardless of current filter
    domains = sorted({u["domain"] for u in all_u if u["domain"]})
    sources = sorted({u.get("dump_source", "") for u in all_u if u.get("dump_source")})
    rate    = round(len(cracked) / len(user_accts) * 100, 1) if user_accts else 0.0

    return jsonify(
        {
            "total_users":      len(user_accts),
            "machine_accounts": len(machines),
            "history_entries":  len(hist_entries),
            "cracked":          len(cracked),
            "uncracked":        len(user_accts) - len(cracked),
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
        if not u["is_history"] and not u["is_machine"]
        and (domain == "all" or u["domain"] == domain)
        and (source == "all" or u.get("dump_source", "") == source)
        and (not excluded or u["domain"] not in excluded)
    ]
    cracked_pws  = [u["password"] for u in scope_users if u["password"]]
    total_scope  = len(scope_users)
    crack_rate   = round(len(cracked_pws) / total_scope * 100, 1) if total_scope else 0.0

    result = run_analysis(cracked_pws)
    result["crack_rate"]   = crack_rate
    result["total_scope"]  = total_scope
    return jsonify(result)


@bp.route("/api/uncracked-hashes")
def uncracked_hashes():
    include_machines = request.args.get("machines", "false") == "true"
    exclude_raw = request.args.get("exclude_domains", "")
    excluded = {x.strip() for x in exclude_raw.split(",") if x.strip()}
    seen:   set  = set()
    hashes: list = []
    for u in session["users"]:
        if u["is_history"] or u["password"]:
            continue
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
    )
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["Username", "Domain", "RID", "LM Hash", "NT Hash", "Password",
                "Shared Count", "Machine", "History", "Hist Index", "Source"])
    for u in users:
        w.writerow(
            [
                u["username"], u["domain"], u["rid"],
                u["lm_hash"], u["nt_hash"],
                u["password"] or "",
                u["password_count"] if u["password"] else "",
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
# Clear
# ---------------------------------------------------------------------------

@bp.route("/api/clear", methods=["POST"])
def clear_all():
    clear_session()
    return jsonify({"success": True})


@bp.route("/api/clear/pot", methods=["POST"])
def clear_pot():
    session["pot_hashes"] = {}
    for u in session["users"]:
        u["password"]       = None
        u["password_count"] = 1
    session["metadata"]["pot_sources"] = []
    save_session()
    return jsonify({"success": True})
