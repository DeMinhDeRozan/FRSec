# FRSec

[![detections-ci](https://github.com/DeMinhDeRozan/FRSec/actions/workflows/detections.yml/badge.svg)](https://github.com/DeMinhDeRozan/FRSec/actions/workflows/detections.yml)

Detection rules for [Fun Reminder](https://github.com/DeMinhDeRozan/FunReminder), a serverless reminder app on AWS. Rules are Sigma, versioned in Git, tested in CI, and deployed to Elastic Security.

This is a lab setup, not a production SIEM.

## Pipeline

```
Lambda (ECS JSON) -> CloudWatch Logs -> pull_logs.py -> Elasticsearch -> Kibana
                                                             ^
rules/*.yml -> CI (lint, tests, throwaway ES) -> deploy_rules.py -> Detection Engine API
```

- The app logs one JSON line per security event, using ECS field names. Prompt text is never logged, only a hash and a length.
- A small script on an Azure VM pulls the logs from CloudWatch into Elasticsearch. Nothing connects into the VM; Elasticsearch and Kibana listen on 127.0.0.1 only.
- The VM runs about 8 hours a day, so rules fire when it is up. No real-time alerting.

## Rules

| Rule | Fires on | Level |
|---|---|---|
| fr_prompt_injection_flagged | prompt flagged by regex layer or the LLM | medium |
| fr_user_banned | account banned after strikes | high |
| fr_ip_banned | guest IP banned (guest-ID rotation) | high |
| fr_banned_access_attempt | banned identity keeps sending | medium |
| fr_token_limit_global | app-wide daily token cap hit | high |
| fr_token_limit_user_or_ip | per-user or per-IP daily cap hit | medium |
| fr_auth_failed | invalid or expired login token | low |
| fr_sweeper_late_reminder | sweeper had to notify a missed reminder | low |
| fr_sweeper_run_failed | sweeper run finished with failures | medium |

ATT&CK tags are best-effort. Check them against attack.mitre.org before relying on them. The prompt injection rule references MITRE ATLAS (AML.T0051) in its description only.

## Layout

```
rules/         Sigma rules
pipeline.yml   pySigma pipeline (target index)
tests/         pytest + sample events (tests/logs/events.jsonl)
tools/         deploy_rules.py, es_integration_test.py
.github/       CI
```

## Tests

Each line in `tests/logs/events.jsonl` lists the rules that must fire on it (`_test.must_match`). Every other rule must stay quiet. Sample data is synthetic (documentation IP ranges, fake IDs).

```bash
pip install -r requirements.txt
python -m pytest tests -q
sigma check rules                 # needs internet (MITRE data download)
python tools/deploy_rules.py --dry-run
```

CI runs lint, pytest, then every converted Lucene query against a throwaway Elasticsearch container and compares the hits with the expectations.

The test matcher supports a small Sigma subset: `field: value`, lists, AND across fields, `condition: selection`. Anything else fails `test_rules_use_supported_subset` instead of silently skipping.

## Deploy

Run on the VM, since Kibana is not exposed:

```bash
git pull
export KIBANA_PASSWORD_ELASTIC=...      # use read -s, keep it out of shell history
python3 tools/deploy_rules.py
```

Creates rules, or updates them in place by `rule_id`. Interval is 5m with a 24h lookback (`LOOKBACK`, `INTERVAL`), because logs arrive in batches after the VM boots.

## Known gaps

- Single-event rules only. No thresholds yet (for example 3 injections in 10 minutes).
- No dashboard in the repo.
- `deploy_rules.py` builds the Kibana rule JSON itself instead of using pySigma's `siem_rule` format, which downloads MITRE data at runtime.
- Login success events are not covered: auth goes through Cognito, not the Lambda.

## Security notes

- No credentials in the repo. The log puller on the VM uses a read-only IAM user (`logs:FilterLogEvents` on two log groups).
- Elasticsearch has security enabled and is bound to localhost. Access is through an SSH tunnel.
- The VM is started and stopped by a separate private repo.
