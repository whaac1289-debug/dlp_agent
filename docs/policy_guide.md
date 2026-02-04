# Policy Guide

## Rule packs
Rule packs live in `/rules`:
- `pii_rules.json`
- `secret_rules.json`
- `compliance_rules.json`
- `default_policy.json`

Use `default_policy.json` as the base policy and extend it with additional rule packs.

## Policy lifecycle
1. Author rule packs and commit to version control.
2. Publish policy updates to tenants through the admin API.
3. Agents fetch active policy snapshots via `/api/v1/agent/policy`.

## Rule loader
The server `policy.rule_loader` module aggregates rule packs and exposes a unified rule list for evaluation.
