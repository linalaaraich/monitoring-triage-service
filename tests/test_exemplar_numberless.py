"""Finding #2 (2026-06-12) — numberless exemplar prose guard.

"Structural not factual" was only an intent until a live verdict copied an
exemplar's example "128Mi". This test removes the *source*: every concrete
example VALUE in archetype prose must be a placeholder (<N>Mi, <X>%, <N>ms,
<K>x, <N>, ...), not a bare number.

PromQL/protocol/HTTP tokens that are real (not example values) are allowed via
a small, explicit allowlist — quantile names (p95 / "95% of requests"), HTTP
status classes (5xx / 503), ports (localhost:8080), the OOMKill exit code
(137), PromQL range/offset windows ([30m], rate(5m)*300), and the ACME
HTTP-01 challenge name. Anything else with two-or-more digits fails the test,
which is the signal that a new example value leaked into the prose.

The numeral-guard validator (app/response_validator) is the runtime backstop;
this test guards the library itself so the backstop rarely has to fire.
"""
import re
from pathlib import Path

import yaml

_LIB = Path(__file__).resolve().parent.parent / "app" / "exemplars" / "library.yaml"

# Prose fields the LLM is tempted to copy facts from.
_PROSE_STR_FIELDS = ("one_line", "human_cause", "rca")
_PROSE_LIST_FIELDS = ("evidence_shape", "actions_shape")

# Structural tokens that legitimately carry digits — real metric/protocol
# vocabulary, NOT example values. Stripped before the bare-number check.
_ALLOWED_TOKEN_PATTERNS = [
    re.compile(r"\bp\d{1,3}\b"),                 # quantile name: p95, p99
    re.compile(r"\b\d{1,3}%\s+of\b"),            # "95% of requests" (quantile prose)
    re.compile(r"\b\d{1,2}xx\b"),                # HTTP status class: 5xx, 4xx
    re.compile(r"\bstatus=\d{3}\b"),             # explicit HTTP status arg: status=503
    re.compile(r"localhost:\d{2,5}"),            # port literal
    re.compile(r"exit\s+\d{2,3}"),               # exit 137 (OOMKill exit code)
    re.compile(r"rate\([^)]*\)\s*\*\s*\d+"),     # PromQL rate(5m)*300 idiom
    re.compile(r"\[\d+[smhd]\]"),                # PromQL window: [30m], [1h], [5m]
    re.compile(r"\(\d+[smhd]\)"),                # PromQL window in parens: (5m)
    re.compile(r"HTTP-\d{2}"),                   # ACME HTTP-01 challenge
    re.compile(r"offset\s+\d+[smhd]"),           # PromQL offset 7d
]

_BARE_NUMBER = re.compile(r"\d{2,}")


def _scrub(text: str) -> str:
    for pat in _ALLOWED_TOKEN_PATTERNS:
        text = pat.sub(" ", text)
    return text


def _iter_prose():
    data = yaml.safe_load(_LIB.read_text())
    entries = list(data.get("exemplars") or [])
    if data.get("default"):
        entries.append(data["default"])
    for ex in entries:
        ex_id = ex.get("id", "(unknown)")
        for f in _PROSE_STR_FIELDS:
            val = ex.get(f)
            if isinstance(val, str):
                yield ex_id, f, val
        for f in _PROSE_LIST_FIELDS:
            for item in (ex.get(f) or []):
                if isinstance(item, str):
                    yield ex_id, f, item


def test_no_bare_example_numbers_in_exemplar_prose():
    offenders = []
    for ex_id, field, text in _iter_prose():
        scrubbed = _scrub(text)
        for m in _BARE_NUMBER.finditer(scrubbed):
            ctx = scrubbed[max(0, m.start() - 25): m.end() + 10].strip()
            offenders.append(f"{ex_id}.{field}: bare number {m.group()!r} near …{ctx}…")
    assert not offenders, (
        "Exemplar prose must be numberless (use <N>Mi/<X>%/<N>ms/<K>x/<N>). "
        "Concrete example values leaked into:\n  " + "\n  ".join(offenders)
    )


def test_placeholders_are_present_where_expected():
    """Sanity: the rewrite actually used placeholders (not just deleted the
    numbers), so the prose still teaches the SHAPE."""
    data = yaml.safe_load(_LIB.read_text())
    oom = next(e for e in data["exemplars"] if e["id"] == "oom-loop")
    assert "<N>Mi" in oom["human_cause"]
