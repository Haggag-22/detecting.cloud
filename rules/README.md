# Detection Rules

Each detection rule lives in its own folder:

```text
rules/<provider>/<rule-slug>/
  meta.json            # id, title, service, severity, tags, ...
  sigma.yml            # canonical Sigma rule
  formats/             # optional translations
    splunk.txt
    cloudtrail.sql
    cloudwatch.txt
    eventbridge.json
    lambda.py
    esql.txt
    datadog.txt
  telemetry.json       # optional sample telemetry context
  investigation.json   # optional SOC investigation steps
  testing.json         # optional lab testing steps
  lifecycle.json       # research / detection-engineering phases
```

The UI loads these folders via `src/data/loadRulesFromDir.ts` and exposes them
through the existing `detections` API in `src/data/detections.ts` (layout unchanged).

## Providers

- `aws/` — AWS CloudTrail / cloud service detections (Sigma + formats + research lifecycle)
- `azure/` — Azure / Entra ID detections (Sigma-only for now)
- `gcp/` — Google Cloud / Workspace detections (Sigma-only for now)
- (future) `kubernetes/`

## Adding a rule

1. Create `rules/aws/<kebab-case-title>/`
2. Add at least `meta.json` and `sigma.yml`
3. Optionally add formats + lifecycle research content
4. Restart / refresh the Vite app — no page layout changes required
