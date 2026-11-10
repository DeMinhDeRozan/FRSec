#!/usr/bin/env python3
"""Convert Sigma rules to Elastic Security (Kibana) detection rules and push them.

Run it ON THE VM (Kibana only listens on 127.0.0.1) after `git pull`:
    export KIBANA_PASSWORD_ELASTIC=...   # password of the 'elastic' user
    python3 tools/deploy_rules.py            # create or update every rule
    python3 tools/deploy_rules.py --dry-run  # print the Kibana JSON, change nothing

Why not pySigma's own `siem_rule` format? It downloads MITRE data at run time, which
fails offline. Building the small rule JSON here keeps interval and lookback under control.

Env: KIBANA_URL (default http://127.0.0.1:5601), KIBANA_USER (default elastic),
     KIBANA_PASSWORD_ELASTIC, LOOKBACK (default now-24h), INTERVAL (default 5m)
"""
import argparse
import base64
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path

from sigma.backends.elasticsearch import LuceneBackend
from sigma.collection import SigmaCollection
from sigma.processing.pipeline import ProcessingPipeline

ROOT = Path(__file__).resolve().parent.parent
SEVERITY = {"informational": ("low", 5), "low": ("low", 21), "medium": ("medium", 47),
            "high": ("high", 73), "critical": ("critical", 99)}
INDEX = ["funreminder-events-*"]


def build_rules(rules_dir=ROOT / "rules", pipeline_file=ROOT / "pipeline.yml",
                lookback="now-24h", interval="5m"):
    pipeline = ProcessingPipeline.from_yaml(Path(pipeline_file).read_text(encoding="utf-8"))
    backend = LuceneBackend(processing_pipeline=pipeline)
    out = []
    for path in sorted(Path(rules_dir).glob("*.yml")):
        coll = SigmaCollection.from_yaml(path.read_text(encoding="utf-8"))
        rule = coll.rules[0]
        query = backend.convert_rule(rule)[0]
        severity, risk = SEVERITY.get(str(rule.level.name.lower()) if rule.level else "medium", ("medium", 47))
        tags = ["Sigma", "funreminder"] + [f"{t.namespace}.{t.name}" for t in rule.tags]
        out.append({
            "rule_id": str(rule.id),
            "name": rule.title,
            "description": (rule.description or rule.title).strip(),
            "type": "query",
            "language": "lucene",
            "query": query,
            "index": INDEX,
            "severity": severity,
            "risk_score": risk,
            "interval": interval,
            "from": lookback,       # lookback must be wide: the VM is off most of the day and logs arrive in batches
            "enabled": True,
            "tags": tags,
            "false_positives": list(rule.falsepositives or []),
            "references": list(rule.references or []),
            "author": [rule.author] if rule.author else [],
            "max_signals": 100,
        })
    return out


def kibana(method, path, body, base, auth):
    req = urllib.request.Request(base + path, method=method,
                                 data=json.dumps(body).encode() if body is not None else None,
                                 headers={"kbn-xsrf": "true", "Content-Type": "application/json",
                                          "Authorization": "Basic " + auth})
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()
    rules = build_rules(lookback=os.environ.get("LOOKBACK", "now-24h"),
                        interval=os.environ.get("INTERVAL", "5m"))
    if a.dry_run:
        print(json.dumps(rules, indent=2))
        return
    pw = os.environ.get("KIBANA_PASSWORD_ELASTIC", "")
    if not pw:
        sys.exit("KIBANA_PASSWORD_ELASTIC is not set")
    base = os.environ.get("KIBANA_URL", "http://127.0.0.1:5601").rstrip("/")
    auth = base64.b64encode(f"{os.environ.get('KIBANA_USER', 'elastic')}:{pw}".encode()).decode()
    failed = 0
    for r in rules:
        code = kibana("POST", "/api/detection_engine/rules", r, base, auth)
        if code == 409:                                   # already exists: update in place
            code = kibana("PUT", "/api/detection_engine/rules", r, base, auth)
        ok = code in (200, 201)
        failed += 0 if ok else 1
        print(("OK  " if ok else f"FAIL({code}) ") + r["name"])
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
