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
from parsers import (
    parse_bloodhound,
    parse_known_passwords,
    parse_list_entries,
    parse_lm_halves,
    parse_pot_file,
    parse_secretsdump,
)
from session_store import (
    add_known_passwords,
    apply_passwords,
    build_hash_groups,
    check_is_tier0,
    clear_session,
    get_filtered_users,
    replace_session,
    save_session,
    session,
)
from session_store import _build_tier0_lookup

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


def _include_machines() -> bool:
    """The global 'include machine accounts' toggle, sent by every analysis call.

    Machine accounts have random 120-char passwords that never crack, so they're
    excluded from stats, analysis and exports by default — including them would
    bury the crack rate. The toggle lets an operator opt them back in.
    """
    return request.args.get("include_machines", "false") == "true"


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
    lm_halves = session.setdefault("lm_halves", {})
    total_new = 0
    lm_new = 0
    names = []
    for f in files:
        text = f.read().decode("utf-8", errors="replace")
        pot = parse_pot_file(text)
        halves = parse_lm_halves(text)
        # Stamp each genuinely new hash with the time it first entered the pot
        for h in pot:
            if h not in session["pot_hashes"]:
                pot_added[h] = now
        session["pot_hashes"].update(pot)
        lm_new += sum(1 for h in halves if h not in lm_halves)
        lm_halves.update(halves)
        total_new += len(pot)
        names.append(f.filename)

    session["metadata"]["pot_sources"] = names
    apply_passwords()
    save_session()
    return jsonify(
        {"success": True, "count": total_new, "lm_halves": lm_new,
         "total_pot": len(session["pot_hashes"]), "filenames": names}
    )


@bp.route("/api/paste/pot", methods=["POST"])
def paste_pot():
    data = request.get_json(silent=True) or {}
    text = data.get("text", "")
    if not text.strip():
        return jsonify({"error": "No text provided"}), 400

    pot = parse_pot_file(text)
    halves = parse_lm_halves(text)
    now = datetime.now().isoformat()
    pot_added = session.setdefault("pot_added", {})
    lm_halves = session.setdefault("lm_halves", {})
    for h in pot:
        if h not in session["pot_hashes"]:
            pot_added[h] = now
    session["pot_hashes"].update(pot)
    lm_new = sum(1 for h in halves if h not in lm_halves)
    lm_halves.update(halves)
    session["metadata"]["pot_sources"] = session["metadata"].get("pot_sources", []) + ["pasted text"]
    apply_passwords()
    save_session()
    return jsonify({"success": True, "count": len(pot), "lm_halves": lm_new,
                    "total_pot": len(session["pot_hashes"])})


# ---------------------------------------------------------------------------
# Ingestion — known passwords
#
# Plaintexts recovered outside the cracking effort (network shares, scripts,
# documentation). Each is NT-hashed on the way in so it can be matched back to
# accounts in the dump — proven correct, but never actually cracked.
# ---------------------------------------------------------------------------

def _known_matched() -> int:
    """How many (non-history) accounts currently hold a known password."""
    return sum(1 for u in session["users"] if u.get("is_known") and not u["is_history"])


@bp.route("/api/upload/known", methods=["POST"])
def upload_known():
    files = request.files.getlist("files")
    if not files or not files[0].filename:
        return jsonify({"error": "No files provided"}), 400

    total_new = 0
    total_read = 0
    names = []
    for f in files:
        text = f.read().decode("utf-8", errors="replace")
        pws = parse_known_passwords(text)
        total_read += len(pws)
        total_new += add_known_passwords(pws)
        names.append(f.filename)

    if total_read == 0:
        return jsonify({"error": "No passwords found in file"}), 400

    session["metadata"]["known_sources"] = (
        session["metadata"].get("known_sources", []) + names
    )
    apply_passwords()
    save_session()
    return jsonify(
        {"success": True, "count": total_new, "read": total_read,
         "total_known": len(session["known_passwords"]),
         "matched": _known_matched(), "filenames": names}
    )


@bp.route("/api/paste/known", methods=["POST"])
def paste_known():
    data = request.get_json(silent=True) or {}
    text = data.get("text", "")
    if not text.strip():
        return jsonify({"error": "No text provided"}), 400

    pws = parse_known_passwords(text)
    if not pws:
        return jsonify({"error": "No passwords found"}), 400

    new = add_known_passwords(pws)
    session["metadata"]["known_sources"] = (
        session["metadata"].get("known_sources", []) + ["pasted text"]
    )
    apply_passwords()
    save_session()
    return jsonify(
        {"success": True, "count": new, "read": len(pws),
         "total_known": len(session["known_passwords"]),
         "matched": _known_matched()}
    )


@bp.route("/api/clear/known", methods=["POST"])
def clear_known():
    session["known_passwords"] = {}
    session["metadata"]["known_sources"] = []
    apply_passwords()  # drop the is_known flag / password from affected accounts
    save_session()
    return jsonify({"success": True})


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
            "has_known":     len(session.get("known_passwords", {})) > 0,
            "known_count":   len(session.get("known_passwords", {})),
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
        hash_type       = request.args.get("hash_type", "all"),
        tag             = request.args.get("tag", ""),
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
    known_count   = 0
    inc_mach      = _include_machines()
    for u in users:
        if u.get("is_history"):
            continue
        if u.get("is_machine") and not inc_mach:
            continue
        if u.get("is_blank"):
            blank_count += 1
        elif u.get("is_known"):
            known_count += 1
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
            "known_count":   known_count,
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
    inc_mach   = _include_machines()
    user_accts = [
        u for u in scoped
        if not u.get("is_krbtgt") and (inc_mach or not u["is_machine"])
    ]
    machines   = [u for u in scoped if u["is_machine"]]
    # History count is always global (not filtered)
    hist_entries = [u for u in all_u if u["is_history"]]
    # "cracked" means a genuinely cracked password. Blank/disabled accounts and
    # known-from-elsewhere passwords are counted separately so they don't
    # inflate the crack rate.
    blank      = [u for u in user_accts if u.get("is_blank")]
    known      = [u for u in user_accts if u.get("is_known")]
    cracked    = [
        u for u in user_accts
        if u["password"] is not None and not u.get("is_blank") and not u.get("is_known")
    ]

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
            "uncracked":        len(user_accts) - len(cracked) - len(blank) - len(known),
            "blank":            len(blank),
            "known":            len(known),
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

    inc_mach = _include_machines()

    scope_users = [
        u for u in session["users"]
        if not u["is_history"] and not u.get("is_krbtgt")
        and (inc_mach or not u["is_machine"])
        and (domain == "all" or u["domain"] == domain)
        and (source == "all" or u.get("dump_source", "") == source)
        and (not excluded or u["domain"] not in excluded)
    ]
    # Blank/disabled accounts (password == "") are excluded from both the crack
    # rate and composition analysis — they aren't a cracking win, and an empty
    # plaintext has no mask, length, or character-class pattern to aggregate.
    # Known passwords are excluded too: they were never cracked, so counting
    # them would overstate what the cracking effort actually achieved.
    cracked_pws   = [u["password"] for u in scope_users if u["password"] and not u.get("is_known")]
    blank_count   = sum(1 for u in scope_users if u.get("is_blank"))
    known_count   = sum(1 for u in scope_users if u.get("is_known"))
    total_scope   = len(scope_users)
    crack_rate    = round(len(cracked_pws) / total_scope * 100, 1) if total_scope else 0.0

    result = run_analysis(cracked_pws)
    result["crack_rate"]    = crack_rate
    result["total_scope"]   = total_scope
    result["blank_count"]   = blank_count
    result["known_count"]   = known_count
    result["cracked_count"] = len(cracked_pws)
    return jsonify(result)


def _group_status(group: list) -> dict:
    """Describe a shared-hash group's plaintext: cracked, known, or unrecovered.

    Every account in a group holds the same NT hash, so one lookup covers all.
    """
    head = group[0]
    return {
        "password": head.get("password"),
        "is_known": bool(head.get("is_known")),
        "cracked":  head.get("password") is not None and not head.get("is_known"),
    }


@bp.route("/api/hash-users")
def hash_users():
    """List every account sharing one NT hash — i.e. sharing one password."""
    h = (request.args.get("hash") or "").strip().lower()
    if len(h) != 32:
        return jsonify({"error": "A 32-character NT hash is required"}), 400

    exclude_raw = request.args.get("exclude_domains", "")
    excluded = {x.strip() for x in exclude_raw.split(",") if x.strip()}
    groups = build_hash_groups(session["users"], _include_machines(), excluded or None)
    members = groups.get(h, [])

    tier0_lookup = _build_tier0_lookup(session.get("tier0_users", []))
    comment_map  = session.get("user_comments", {})

    out = []
    for u in sorted(members, key=lambda x: (x["domain"].lower(), x["username"].lower())):
        out.append(
            {
                "username":    u["username"],
                "domain":      u["domain"],
                "rid":         u["rid"],
                "is_machine":  u["is_machine"],
                "is_krbtgt":   bool(u.get("is_krbtgt")),
                "is_tier0":    bool(u.get("is_krbtgt"))
                               or check_is_tier0(u["username"], u["domain"], tier0_lookup),
                "dump_source": u.get("dump_source", ""),
                "comment":     comment_map.get(
                    f"{u['domain'].lower()}/{u['username'].lower()}", ""
                ),
            }
        )

    status = (_group_status(members) if members
              else {"password": None, "is_known": False, "cracked": False})
    return jsonify({"hash": h, "count": len(out), "users": out, **status})


@bp.route("/api/analysis/hash-reuse")
def get_hash_reuse():
    """Shared-password clusters, found by grouping identical NT hashes.

    Independent of the pot file — this is the one reuse measure that still works
    when nothing has been cracked, which is exactly when it matters most.
    """
    exclude_raw = request.args.get("exclude_domains", "")
    excluded = {x.strip() for x in exclude_raw.split(",") if x.strip()}
    limit = min(200, max(1, int(request.args.get("limit", 30))))

    groups = build_hash_groups(session["users"], _include_machines(), excluded or None)
    shared = {h: g for h, g in groups.items() if len(g) > 1}

    total_accounts  = sum(len(g) for g in groups.values())
    shared_accounts = sum(len(g) for g in shared.values())
    uncracked = [g for g in shared.values() if g[0].get("password") is None]

    tier0_lookup = _build_tier0_lookup(session.get("tier0_users", []))

    top = sorted(shared.items(), key=lambda kv: (-len(kv[1]), kv[0]))[:limit]
    out_groups = []
    for h, g in top:
        ordered = sorted(g, key=lambda x: (x["domain"].lower(), x["username"].lower()))
        out_groups.append(
            {
                "hash":     h,
                "count":    len(g),
                "members":  [
                    (f"{u['domain']}\\{u['username']}" if u["domain"] else u["username"])
                    for u in ordered[:5]
                ],
                "has_tier0": any(
                    u.get("is_krbtgt")
                    or check_is_tier0(u["username"], u["domain"], tier0_lookup)
                    for u in g
                ),
                "has_machine": any(u["is_machine"] for u in g),
                **_group_status(g),
            }
        )

    return jsonify(
        {
            "total_accounts":     total_accounts,
            "shared_groups":      len(shared),
            "shared_accounts":    shared_accounts,
            "shared_pct":         round(shared_accounts / total_accounts * 100, 1) if total_accounts else 0.0,
            "max_group":          max((len(g) for g in shared.values()), default=0),
            "uncracked_groups":   len(uncracked),
            "uncracked_accounts": sum(len(g) for g in uncracked),
            "groups":             out_groups,
        }
    )


@bp.route("/api/uncracked-hashes")
def uncracked_hashes():
    include_machines = (
        request.args.get("machines", "false") == "true" or _include_machines()
    )
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
    inc_mach = _include_machines()
    users = session.get("users", [])
    domains = {}
    for u in users:
        if u["is_history"] or u.get("is_krbtgt"):
            continue
        if u["is_machine"] and not inc_mach:
            continue
        if excluded and u["domain"] in excluded:
            continue
        d = u["domain"]
        if d not in domains:
            domains[d] = {"total": 0, "cracked": 0}
        domains[d]["total"] += 1
        # Same definition of "cracked" as /api/stats: a real recovered password.
        # Blank/disabled accounts and known-from-elsewhere passwords are not
        # cracks, so this rate matches the one on the Overview tab.
        if u["password"] is not None and not u.get("is_blank") and not u.get("is_known"):
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
        hash_type       = request.args.get("hash_type", "all"),
        tag             = request.args.get("tag", ""),
    )
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["Username", "Domain", "RID", "LM Hash", "NT Hash", "Password",
                "Password Origin", "Blank/Disabled", "LM Password", "Cracked At",
                "Shared Count", "Accounts Sharing Hash", "Machine", "History",
                "Hist Index", "Source", "AD Enabled", "Groups", "Group Tags"])
    for u in users:
        if u.get("is_blank"):
            origin = "Blank/Disabled"
        elif u.get("is_known"):
            origin = "Known"
        elif u["password"] is not None:
            origin = "Cracked"
        else:
            origin = ""
        w.writerow(
            [
                u["username"], u["domain"], u["rid"],
                u["lm_hash"], u["nt_hash"],
                "(blank)" if u.get("is_blank") else (u["password"] or ""),
                origin,
                "Yes" if u.get("is_blank") else "No",
                u.get("lm_password") or "",
                u.get("cracked_at") or "",
                u["password_count"] if u["password"] is not None else "",
                u.get("hash_count", 1),
                "Yes" if u["is_machine"] else "No",
                "Yes" if u["is_history"] else "No",
                u["hist_index"] if u["hist_index"] >= 0 else "",
                u.get("dump_source", ""),
                "" if u.get("enabled") is None else ("Yes" if u.get("enabled") else "No"),
                "; ".join(u.get("groups", [])),
                "; ".join(u.get("tags", [])),
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

    hash_groups = build_hash_groups(
        session["users"], _include_machines(), excluded or None
    )
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
                # Same NT hash ⇒ same plaintext source, so one flag covers the group
                origin = "Known" if any(u.get("is_known") for u in group) else "Cracked"
                header = f"Password reused {user_count} times — {short_hash} ({origin}{pw_part})"
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
    """Export all unique recovered passwords as a plain-text wordlist.

    Known passwords are included here — they're valid plaintexts from this
    environment and are exactly what you want in a targeted wordlist, even
    though they don't count towards the crack rate.
    """
    inc_mach = _include_machines()

    def in_scope(u: dict) -> bool:
        return bool(u["password"]) and not u["is_history"] and (inc_mach or not u["is_machine"])

    seen: set   = set()
    words: list = []
    for u in session["users"]:
        if in_scope(u):
            pw = u["password"]
            if pw not in seen:
                seen.add(pw)
                words.append(pw)
    # Sort by frequency (most common first) using pot_hashes reverse lookup
    pw_freq: dict[str, int] = {}
    for u in session["users"]:
        if in_scope(u):
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
    inc_mach  = _include_machines()
    cracked_pws = [
        u["password"]
        for u in session["users"]
        if u["password"] and not u["is_history"] and (inc_mach or not u["is_machine"])
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
    users = parse_list_entries(text)
    session["tier0_users"] = users
    save_session()
    return jsonify({"success": True, "count": len(users)})


@bp.route("/api/tier0/paste", methods=["POST"])
def paste_tier0():
    data = request.get_json(silent=True) or {}
    text = data.get("text", "")
    if not text.strip():
        return jsonify({"error": "No text provided"}), 400
    users = parse_list_entries(text)
    session["tier0_users"] = users
    save_session()
    return jsonify({"success": True, "count": len(users)})


# ---------------------------------------------------------------------------
# BloodHound import — group membership + enabled status
#
# A neo4j CSV export (from the Import BloodHound Cypher query) maps each account
# to its groups and whether it's enabled. Matched back to NTDS accounts by SAM
# name + domain, it lets the table mark disabled accounts and show per-user
# group membership, and powers the "Group member" search.
# ---------------------------------------------------------------------------

def _bloodhound_summary(records: list) -> dict:
    """Counts for the UI status line."""
    disabled = sum(1 for r in records if r.get("enabled") is False)
    tier0    = sum(1 for r in records if r.get("tier0") or r.get("tier0_groups"))
    return {"count": len(records), "disabled": disabled, "tier0": tier0}


@bp.route("/api/bloodhound", methods=["GET"])
def get_bloodhound():
    records = session.get("bloodhound", [])
    return jsonify(_bloodhound_summary(records))


@bp.route("/api/bloodhound/upload", methods=["POST"])
def upload_bloodhound():
    f = request.files.get("file")
    if not f:
        return jsonify({"error": "No file provided"}), 400
    text = f.read().decode("utf-8-sig", errors="replace")
    records = parse_bloodhound(text)
    if not records:
        return jsonify({"error": "No accounts found — expected a neo4j CSV or JSON export with "
                                 "samaccountname / name / enabled / groups columns"}), 400
    session["bloodhound"] = records
    save_session()
    return jsonify({"success": True, **_bloodhound_summary(records)})


@bp.route("/api/bloodhound/paste", methods=["POST"])
def paste_bloodhound():
    data = request.get_json(silent=True) or {}
    text = data.get("text", "")
    if not text.strip():
        return jsonify({"error": "No text provided"}), 400
    records = parse_bloodhound(text)
    if not records:
        return jsonify({"error": "No accounts found — expected a neo4j CSV or JSON export with "
                                 "samaccountname / name / enabled / groups columns"}), 400
    session["bloodhound"] = records
    save_session()
    return jsonify({"success": True, **_bloodhound_summary(records)})


@bp.route("/api/bloodhound", methods=["DELETE"])
def clear_bloodhound():
    session["bloodhound"] = []
    save_session()
    return jsonify({"success": True})


# ---------------------------------------------------------------------------
# Tags — free-text labels ("privileged", "bypasses mfa", …) applied either to a
# BloodHound group (flags every member) or directly to an account (works even
# for accounts BloodHound never found). Tagged from the per-user groups popup;
# each distinct tag becomes a filter in the user-scope dropdown.
# ---------------------------------------------------------------------------

def _distinct_tags(*tag_maps: dict) -> list:
    """All distinct tags across one or more {key: [tags]} maps, sorted ci."""
    seen: dict = {}
    for tmap in tag_maps:
        for tags in (tmap or {}).values():
            for t in (tags or []):
                seen.setdefault(t.lower(), t)
    return [seen[k] for k in sorted(seen)]


def _normalize_tag_list(raw) -> list | None:
    """Trim, drop blanks, de-dupe case-insensitively. None if not a list."""
    if not isinstance(raw, list):
        return None
    seen: dict = {}
    for t in raw:
        t = str(t).strip()
        if t:
            seen.setdefault(t.lower(), t)
    return list(seen.values())


@bp.route("/api/group-tags", methods=["GET"])
def get_group_tags():
    gt = session.get("group_tags", {})
    ut = session.get("user_tags", {})
    return jsonify({"tags": gt, "user_tags": ut, "all_tags": _distinct_tags(gt, ut)})


@bp.route("/api/group-tags", methods=["POST"])
def set_group_tags():
    """Replace the tag list for one group. An empty list clears it."""
    data  = request.get_json(silent=True) or {}
    group = (data.get("group") or "").strip()
    if not group:
        return jsonify({"error": "No group provided"}), 400

    tags = _normalize_tag_list(data.get("tags", []))
    if tags is None:
        return jsonify({"error": "tags must be a list"}), 400

    gt = session.setdefault("group_tags", {})
    if tags:
        gt[group] = tags
    else:
        gt.pop(group, None)
    save_session()
    return jsonify({"success": True, "group": group, "tags": tags,
                    "all_tags": _distinct_tags(gt, session.get("user_tags", {}))})


@bp.route("/api/user-tags", methods=["POST"])
def set_user_tags():
    """Replace the tag list for one account, keyed 'domain/username' (lowercase)."""
    data = request.get_json(silent=True) or {}
    key  = (data.get("key") or "").strip().lower()
    if not key:
        return jsonify({"error": "No account key provided"}), 400

    tags = _normalize_tag_list(data.get("tags", []))
    if tags is None:
        return jsonify({"error": "tags must be a list"}), 400

    ut = session.setdefault("user_tags", {})
    if tags:
        ut[key] = tags
    else:
        ut.pop(key, None)
    save_session()
    return jsonify({"success": True, "key": key, "tags": tags,
                    "all_tags": _distinct_tags(session.get("group_tags", {}), ut)})


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
    session["lm_halves"] = {}
    session["metadata"]["pot_sources"] = []
    apply_passwords()  # re-derive password/is_blank so blank accounts stay marked cracked
    save_session()
    return jsonify({"success": True})
