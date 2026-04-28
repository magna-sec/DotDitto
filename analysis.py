"""
DotDitto — analysis.py
Password mask analysis, word extraction, prefix analysis, and complexity stats.
"""
import re
from collections import Counter

# ---------------------------------------------------------------------------
# Mask helpers
# ---------------------------------------------------------------------------

def password_to_mask(password: str) -> str:
    """Convert a plaintext password to a hashcat ?u/?l/?d/?s mask."""
    parts = []
    for ch in password:
        if ch.isupper():
            parts.append("?u")
        elif ch.islower():
            parts.append("?l")
        elif ch.isdigit():
            parts.append("?d")
        else:
            parts.append("?s")
    return "".join(parts)


def mask_to_pattern(mask: str) -> str:
    """Convert a hashcat mask to a compact human-readable pattern.

    '?u?l?l?l?l?l?l?l?d?d?s'  →  'U  l×7  d×2  s'
    """
    if not mask:
        return ""
    tokens = [mask[i: i + 2] for i in range(0, len(mask), 2)]
    if not tokens:
        return ""

    groups: list[tuple[str, int]] = []
    cur, cnt = tokens[0], 1
    for t in tokens[1:]:
        if t == cur:
            cnt += 1
        else:
            groups.append((cur, cnt))
            cur, cnt = t, 1
    groups.append((cur, cnt))

    labels = {"?u": "U", "?l": "l", "?d": "d", "?s": "s"}
    return "  ".join(
        labels.get(tok, "?") if n == 1 else f"{labels.get(tok, '?')}×{n}"
        for tok, n in groups
    )


# ---------------------------------------------------------------------------
# Word / token extraction
# ---------------------------------------------------------------------------

# Split on digit runs, special-char runs, and case boundaries
_WORD_SPLIT_RE = re.compile(r"[^a-zA-Z]+|(?<=[a-z])(?=[A-Z])")


def extract_words(password: str) -> list[str]:
    """Split a password into alphabetic word tokens (min 2 chars, lowercased)."""
    tokens = _WORD_SPLIT_RE.split(password)
    return [t.lower() for t in tokens if len(t) >= 2]


def extract_prefix(password: str) -> str | None:
    """Return the leading alphabetic segment of a password (lowercased), or None."""
    m = re.match(r"^([a-zA-Z]{2,})", password)
    return m.group(1).lower() if m else None


# ---------------------------------------------------------------------------
# Full analysis
# ---------------------------------------------------------------------------

# Matches 4-digit years commonly appended to AD passwords (1970–2030)
_YEAR_RE = re.compile(r"(?:19[789]\d|20[012]\d|2030)")


def run_analysis(cracked_passwords: list[str]) -> dict:
    """Compute all analysis metrics for a list of plaintext passwords.

    Returns a dict ready to be JSON-serialised.
    """
    if not cracked_passwords:
        return {
            "total": 0,
            "unique_masks": 0,
            "masks": [],
            "lengths": [],
            "char_classes": {},
            "top_words": [],
            "top_prefixes": [],
            "complexity": {},
            "reuse": {
                "unique_passwords": 0,
                "reused_password_count": 0,
                "reused_user_count": 0,
                "max_reuse": 0,
                "reuse_pct": 0.0,
                "unique_pct": 0.0,
            },
            "year_pct": 0.0,
        }

    total = len(cracked_passwords)

    # ── Mask frequency ──────────────────────────────────────────────────────
    mask_map: dict[str, dict] = {}
    for pw in cracked_passwords:
        m = password_to_mask(pw)
        if m not in mask_map:
            mask_map[m] = {
                "mask": m,
                "pattern": mask_to_pattern(m),
                "length": len(pw),
                "count": 0,
                "examples": [],
            }
        mask_map[m]["count"] += 1
        ex = mask_map[m]["examples"]
        if len(ex) < 3 and pw not in ex:
            ex.append(pw)

    top_masks = sorted(mask_map.values(), key=lambda x: x["count"], reverse=True)[:30]

    # ── Length distribution ─────────────────────────────────────────────────
    length_dist: dict[int, int] = {}
    for pw in cracked_passwords:
        ln = len(pw)
        length_dist[ln] = length_dist.get(ln, 0) + 1
    lengths = sorted(
        [{"length": k, "count": v} for k, v in length_dist.items()],
        key=lambda x: x["length"],
    )

    # ── Character-class presence rates ─────────────────────────────────────
    def pct(pred) -> float:
        return round(sum(1 for pw in cracked_passwords if pred(pw)) / total * 100, 1)

    char_classes = {
        "upper":   pct(lambda p: any(c.isupper() for c in p)),
        "lower":   pct(lambda p: any(c.islower() for c in p)),
        "digit":   pct(lambda p: any(c.isdigit() for c in p)),
        "special": pct(lambda p: any(not c.isalnum() for c in p)),
    }

    # ── Top words ───────────────────────────────────────────────────────────
    word_counter: Counter = Counter()
    for pw in cracked_passwords:
        for word in extract_words(pw):
            word_counter[word] += 1

    top_words = [
        {"word": w, "count": c}
        for w, c in word_counter.most_common(30)
    ]

    # ── Top prefixes ────────────────────────────────────────────────────────
    prefix_counter: Counter = Counter()
    for pw in cracked_passwords:
        p = extract_prefix(pw)
        if p:
            prefix_counter[p] += 1

    top_prefixes = [
        {"prefix": p, "count": c}
        for p, c in prefix_counter.most_common(20)
    ]

    # ── Complexity breakdown ────────────────────────────────────────────────
    def complexity_class(pw: str) -> str:
        has_upper   = any(c.isupper() for c in pw)
        has_lower   = any(c.islower() for c in pw)
        has_digit   = any(c.isdigit() for c in pw)
        has_special = any(not c.isalnum() for c in pw)
        classes = sum([has_upper, has_lower, has_digit, has_special])
        if classes == 1:
            return "single_class"
        elif classes == 2:
            return "two_class"
        elif classes == 3:
            return "three_class"
        else:
            return "four_class"

    complexity_counts: dict[str, int] = {
        "single_class": 0,
        "two_class": 0,
        "three_class": 0,
        "four_class": 0,
    }
    for pw in cracked_passwords:
        complexity_counts[complexity_class(pw)] += 1

    complexity = {
        k: {"count": v, "pct": round(v / total * 100, 1)}
        for k, v in complexity_counts.items()
    }

    # Average and median length
    sorted_lengths = sorted(len(pw) for pw in cracked_passwords)
    avg_len = round(sum(sorted_lengths) / total, 1)
    mid = total // 2
    median_len = (
        sorted_lengths[mid]
        if total % 2 != 0
        else (sorted_lengths[mid - 1] + sorted_lengths[mid]) / 2
    )

    complexity["avg_length"]    = avg_len
    complexity["median_length"] = median_len
    complexity["min_length"]    = sorted_lengths[0]
    complexity["max_length"]    = sorted_lengths[-1]

    # ── Reuse / uniqueness ──────────────────────────────────────────────────
    pw_counter: Counter = Counter(cracked_passwords)
    unique_pws    = len(pw_counter)
    # Passwords (not users) that appear more than once
    reused_pw_ct  = sum(1 for c in pw_counter.values() if c > 1)
    # Users whose password is shared with at least one other account
    reused_usr_ct = sum(c for c in pw_counter.values() if c > 1)
    max_reuse     = pw_counter.most_common(1)[0][1] if pw_counter else 0

    reuse = {
        "unique_passwords":    unique_pws,
        "reused_password_count": reused_pw_ct,
        "reused_user_count":   reused_usr_ct,
        "max_reuse":           max_reuse,
        "reuse_pct":   round(reused_usr_ct / total * 100, 1) if total else 0.0,
        "unique_pct":  round(unique_pws    / total * 100, 1) if total else 0.0,
    }

    # ── Year patterns ───────────────────────────────────────────────────────
    year_count = sum(1 for pw in cracked_passwords if _YEAR_RE.search(pw))
    year_pct   = round(year_count / total * 100, 1) if total else 0.0

    return {
        "total":        total,
        "unique_masks": len(mask_map),
        "masks":        top_masks,
        "lengths":      lengths,
        "char_classes": char_classes,
        "top_words":    top_words,
        "top_prefixes": top_prefixes,
        "complexity":   complexity,
        "reuse":        reuse,
        "year_pct":     year_pct,
    }


# ---------------------------------------------------------------------------
# Word-frequency wordlist builder
# ---------------------------------------------------------------------------

def build_word_wordlist(cracked_passwords: list[str], min_count: int = 2) -> list[str]:
    """Return words extracted from passwords sorted by frequency (most common first).

    Only words that appear at least *min_count* times are included.
    """
    counter: Counter = Counter()
    for pw in cracked_passwords:
        for word in extract_words(pw):
            counter[word] += 1

    return [word for word, cnt in counter.most_common() if cnt >= min_count]
