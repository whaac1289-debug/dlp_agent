# Incident Response

## Triage workflow
1. Identify the alert and affected tenant.
2. Validate event metadata and policy decision context.
3. Escalate to blocking controls if needed.

## Containment steps
- Quarantine or shadow-copy impacted files on endpoints.
- Rotate agent shared secrets for compromised agents.
- Disable affected user accounts or revoke tokens.

## Post-incident
- Capture event timelines and export SIEM summaries.
- Review policy rules for tuning opportunities.
- Document root cause and follow-up controls.
