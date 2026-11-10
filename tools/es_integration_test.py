#!/usr/bin/env python3
"""Run the converted Lucene queries against a REAL Elasticsearch (used in CI with a throw-away
container) and check each rule hits exactly the test events that expect it.

    ES_URL=http://localhost:9200 python3 tools/es_integration_test.py
"""
import json
import os
import sys
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from deploy_rules import ROOT, build_rules  # noqa: E402

ES = os.environ.get("ES_URL", "http://localhost:9200").rstrip("/")
INDEX = "funreminder-events-test"


def es(method, path, body=None, raw=False):
    data = (body.encode() if raw else json.dumps(body).encode()) if body is not None else None
    req = urllib.request.Request(ES + path, data=data, method=method,
                                 headers={"Content-Type": "application/x-ndjson" if raw else "application/json"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.loads(r.read().decode() or "{}")


def main():
    events = [json.loads(l) for l in (ROOT / "tests/logs/events.jsonl").read_text(encoding="utf-8").splitlines() if l.strip()]
    es("PUT", f"/{INDEX}", {"mappings": {"dynamic_templates": [{"s": {"match_mapping_type": "string",
        "mapping": {"type": "keyword", "ignore_above": 1024}}}],
        "properties": {"@timestamp": {"type": "date"}, "source": {"properties": {"ip": {"type": "ip"}}}}}})
    lines = []
    for i, e in enumerate(events):
        e = {k: v for k, v in e.items() if k != "_test"}
        lines += [json.dumps({"index": {"_index": INDEX, "_id": str(i)}}), json.dumps(e)]
    res = es("POST", "/_bulk?refresh=true", "\n".join(lines) + "\n", raw=True)
    assert not res.get("errors"), res

    by_id = {Path(p).stem: __import__("yaml").safe_load(Path(p).read_text())["id"]
             for p in map(str, sorted((ROOT / "rules").glob("*.yml")))}
    rules = {r["rule_id"]: r for r in build_rules()}
    bad = 0
    for name, rid in by_id.items():
        expected = {str(i) for i, e in enumerate(events) if name in e["_test"]["must_match"]}
        hits = es("POST", f"/{INDEX}/_search", {"size": 100, "_source": False,
                  "query": {"query_string": {"query": rules[rid]["query"]}}})
        got = {h["_id"] for h in hits["hits"]["hits"]}
        ok = got == expected
        bad += 0 if ok else 1
        print(("OK   " if ok else "FAIL ") + name, "expected", sorted(expected), "got", sorted(got))
    es("DELETE", f"/{INDEX}")
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
