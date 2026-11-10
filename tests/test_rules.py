"""Rule tests. Each line of tests/logs/events.jsonl carries `_test.must_match`: the rule file
names that MUST fire on it. Every other rule must stay silent (no false alerts).

The matcher below is a small Sigma subset (field: value | list, AND across fields,
condition: selection). Rules outside that subset fail test_rules_use_supported_subset,
so a new feature can't silently skip testing."""
import json
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
RULES = {p.stem: yaml.safe_load(p.read_text(encoding="utf-8")) for p in sorted((ROOT / "rules").glob("*.yml"))}
EVENTS = [json.loads(l) for l in (ROOT / "tests/logs/events.jsonl").read_text(encoding="utf-8").splitlines() if l.strip()]
LEVELS = {"informational", "low", "medium", "high", "critical"}


def flatten(d, prefix=""):
    out = {}
    for k, v in d.items():
        key = f"{prefix}{k}"
        if isinstance(v, dict):
            out.update(flatten(v, key + "."))
        else:
            out[key] = v
    return out


def matches(rule, event):
    flat = flatten({k: v for k, v in event.items() if k != "_test"})
    for field, want in rule["detection"]["selection"].items():
        wants = want if isinstance(want, list) else [want]
        got = flat.get(field)
        if got is None or str(got).lower() not in {str(w).lower() for w in wants}:
            return False
    return True


def test_rules_use_supported_subset():
    for name, r in RULES.items():
        det = r["detection"]
        assert set(det) == {"selection", "condition"}, f"{name}: only selection+condition supported"
        assert det["condition"] == "selection", name
        assert all("|" not in f for f in det["selection"]), f"{name}: field modifiers not supported by the test matcher"


def test_rule_metadata():
    ids = [r["id"] for r in RULES.values()]
    assert len(ids) == len(set(ids)), "duplicate rule ids"
    for name, r in RULES.items():
        assert r["level"] in LEVELS, name
        assert r["description"].strip(), name
        assert r.get("falsepositives"), f"{name}: document false positives"
        assert r["logsource"]["product"] == "funreminder", name
        for t in r.get("tags", []):
            assert t.startswith("attack."), f"{name}: unexpected tag {t}"


@pytest.mark.parametrize("event", EVENTS, ids=lambda e: e["_test"]["name"])
def test_each_event_fires_exactly_the_expected_rules(event):
    fired = sorted(n for n, r in RULES.items() if matches(r, event))
    assert fired == sorted(event["_test"]["must_match"])


def test_every_rule_has_a_positive_test():
    covered = {m for e in EVENTS for m in e["_test"]["must_match"]}
    assert covered == set(RULES), f"rules without a positive test: {set(RULES) - covered}"


def test_logs_contain_no_prompt_text():
    for e in EVENTS:
        assert "prompt" not in e.get("funreminder", {}), "raw prompt must never be logged"


def test_conversion_to_lucene():
    pytest.importorskip("sigma.backends.elasticsearch")
    import sys
    sys.path.insert(0, str(ROOT / "tools"))
    from deploy_rules import build_rules
    built = {r["rule_id"]: r for r in build_rules()}
    assert len(built) == len(RULES)
    for name, r in RULES.items():
        q = built[r["id"]]["query"]
        assert "event.action" in q and "event.dataset" in q, name
        assert built[r["id"]]["language"] == "lucene"
