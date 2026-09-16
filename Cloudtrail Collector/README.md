# Ventra (CloudTrail collector) + SOF-ELK Ingestion Pipeline

CLI name: **`ventra`**. Collect CloudTrail with:

```bash
ventra collect cloudtrail --mode trail   # copy from trail S3 (preferred)
ventra collect cloudtrail --mode s3        # same as trail (S3 object collection)
ventra collect cloudtrail --mode lookup    # LookupEvents API backfill
```

**One-time install** (then always use `ventra`, not `python -m collector`):

```bash
cd "Cloudtrail Collector"
bash install-ventra.sh
```

From the parent repo:

```bash
bash scripts/ventra collect cloudtrail --help
```

Optional: `source "Cloudtrail Collector/.venv/bin/activate"` then `ventra ...` anywhere.  
Legacy flat CLI: `cloudtrail-collector` (deprecated).

---

Collects AWS CloudTrail logs from a client account into our own S3 bucket as a
frozen evidence set, then ingests them into our Elasticsearch stack using
SOF-ELK's parsing configs so we get SOF-ELK's schema and dashboards.

Built for DFIR engagements at terabyte scale. Chain of custody matters: this
evidence may be challenged later.

```
Collector (Python, boto3)
  ├─ Mode A: trail   → server-side S3 CopyObject into our bucket
  └─ Mode B: lookup  → LookupEvents API → gzipped NDJSON → multipart upload
                            ↓
            Evidence bucket, per-engagement prefix
                            ↓
            S3 ObjectCreated → SNS → SQS
                            ↓
            Logstash workers (SQS-driven S3 input)
              → gzip → json → split on Records (Mode A only)
              → SOF-ELK 6901-aws.conf
              → our Elasticsearch
```

---

## Read this first: the state of this repo's SOF-ELK checkout

Two things differ from a clean upstream SOF-ELK, and both affect how you update.

**1. `sof-elk-repo/` carries local modifications.** `git status` in that
directory shows `6901-aws.conf`, `6801-azure.conf`, `6950-gcp.conf`, and
`9900-output-elasticsearch-consolidated.conf` as modified. The `6901-aws.conf`
change is substantial: upstream's `mutate { rename }` block was rewritten as a
`ruby` filter using a non-destructive `copy()` helper plus an idempotency guard.
That is the format this project has standardised on, and the configs here are
written to match it.

The consequence is that `git pull` in `sof-elk-repo/` **will conflict** on those
files. That is the accepted trade-off, not an accident. When you update
upstream:

```bash
cd sof-elk-repo
git stash                  # park local modifications
git pull
git stash pop              # resolve conflicts against the new upstream
```

**2. Some custom configs were written *into* the SOF-ELK checkout.** These are
untracked files that do not belong to upstream:

| File | Status |
|---|---|
| `0005-preprocess-aws-s3.conf` | **Superseded** by `logstash/0007-preprocess-evidence-cloudtrail.conf` |
| `9997-input-s3-aws.conf` | **Superseded** by `logstash/0002-input-sqs-s3-evidence.conf` |
| `0006-preprocess-aws-vpcflow-s3.conf` | Unrelated (VPC flow) — leave alone |
| `9998-input-s3-vpcflow.conf` | Unrelated (VPC flow) — leave alone |
| `1002-preprocess-detection-rules-logs-index.conf` | Unrelated — leave alone |

Move the two superseded files out before starting this pipeline, or they will
double-process every object:

```bash
mkdir -p sof-elk-repo/.superseded
mv sof-elk-repo/configfiles/0005-preprocess-aws-s3.conf \
   sof-elk-repo/configfiles/9997-input-s3-aws.conf \
   sof-elk-repo/.superseded/
```

`0005` is specifically harmful if left in place: it does an *untargeted* JSON
parse, which leaves Mode B's fields at the top level where `6901-aws.conf`
cannot see them.

Everything this project adds lives **outside** `sof-elk-repo/` and is bind-
mounted in, so no new local modifications accumulate there.

---

## Prerequisites

- Python 3.11+ and `boto3`
- Terraform 1.5+ (for the ingest wiring)
- Docker + Docker Compose (the existing stack in the parent directory)
- AWS credentials for the source account (read) and our account (write)

```bash
cd "Cloudtrail Collector"
python3 -m venv .venv
./.venv/bin/pip install -e ".[dev]"
./.venv/bin/python -m pytest        # 125 tests, no AWS calls
```

### SOF-ELK repo placement

SOF-ELK's configs reference `/usr/local/sof-elk/grok-patterns/` and
`/usr/local/sof-elk/lib/` as **absolute paths**. That location is not optional
— `6901-aws.conf` alone contains
`patterns_dir => [ "/usr/local/sof-elk/grok-patterns" ]`.

In this Docker stack that requirement is already satisfied by a bind mount in
`docker-compose.yml`:

```yaml
- ./sof-elk-repo:/usr/local/sof-elk:ro
```

So there is nothing to clone — just confirm the mount is intact:

```bash
docker compose exec logstash ls /usr/local/sof-elk/grok-patterns | head
```

If you ever run Logstash outside this stack, clone SOF-ELK to exactly
`/usr/local/sof-elk/` on that host.

> **SOF-ELK's own documentation states these configs are supported only on the
> SOF-ELK VM.** Running them standalone works, but expect friction: hardcoded
> absolute paths, assumptions about plugin versions, and helper scripts that
> assume an unauthenticated Elasticsearch. `supporting-scripts/load_all_dashboards.sh`
> is a concrete example — it curls ES with no credentials and reads
> `/usr/share/kibana/package.json`, neither of which holds here, which is why
> this project ships its own template loader.

---

## Setup

### 1. Load the Elasticsearch index templates — before any ingest

Without these, Elasticsearch infers mappings dynamically: `source.ip` becomes a
string instead of an `ip`, ports become strings instead of integers, and the
SOF-ELK dashboards render empty or wrong **with no error anywhere**. Mappings
cannot be changed in place, so the only fix afterwards is a reindex.

```bash
ES_PASSWORD="$ELASTIC_PASSWORD" ./scripts/load-sof-elk-templates.sh \
  http://localhost:9200 ../sof-elk-repo
```

Component templates load first (index templates reference them by name via
`composed_of`, and ES rejects an index template whose components do not exist).

Verify:

```bash
curl -s -u "elastic:$ELASTIC_PASSWORD" localhost:9200/_index_template/aws | jq '.index_templates[0].index_template.index_patterns'
```

Expect `["aws-*"]`.

### 2. Deploy the ingest wiring

```bash
cd terraform
cp terraform.tfvars.example terraform.tfvars   # then edit
terraform init && terraform apply
```

See [terraform/README.md](terraform/README.md) for why this uses SQS rather
than Logstash's bucket-polling S3 input, and for the footguns (one notification
config per bucket; Object Lock is permanent; visibility timeout must exceed
per-object processing time).

### 3. Wire up Logstash

```bash
cp logstash/docker-compose.override.yml ../docker-compose.override.yml
```

Add to the stack's `.env`:

```bash
SQS_QUEUE_NAME=ct-evidence-IR-2026-0142-ingest
AWS_REGION=us-east-1
ELASTICSEARCH_HOST=http://elasticsearch:9200
```

```bash
cd .. && docker compose up -d --build logstash
```

The override bind-mounts each config as an individual **file** into
`/usr/share/logstash/pipeline/`, which is what keeps them out of
`sof-elk-repo/`. Note that `9900-output-elasticsearch-evidence.conf` is mounted
*over* SOF-ELK's `9900-output-elasticsearch-consolidated.conf` — replacing it,
not adding to it. Logstash concatenates every `output` block it finds, so two
elasticsearch outputs would index every event twice.

The build adds `logstash-input-s3-sns-sqs`. The bundled AWS integration has `s3`
and `sqs` inputs but nothing that reads S3 objects *in response to* queue
messages.

Validate the pipeline before pointing real evidence at it:

```bash
docker compose exec logstash logstash --config.test_and_exit \
  --path.settings /usr/share/logstash/config
```

---

## Running the collector

`--mode` is **required and has no default**. The two modes produce evidence sets
with materially different fidelity, and choosing wrong is not recoverable after
the fact. Omitting it prints the full explanation and exits.

### Mode A — trail (preferred whenever a trail exists)

Full fidelity: management events, data events, and Insights, exactly as the
source trail recorded them. No history limit. Copies are server-side, so object
bytes never transit the collector host.

```bash
ventra collect cloudtrail \
  --mode trail \
  --engagement-id IR-2026-0142 \
  --trail-name management-trail \
  --dest-bucket our-dfir-evidence \
  --start 2026-08-01 --end 2026-08-15 \
  --profile client --dest-profile ours \
  --concurrency 16
```

`--trail-name` calls **`cloudtrail:DescribeTrails`** and fills **`--bucket`** and
the trail’s **`S3KeyPrefix`** as **`--prefix`** (unless you override). Use
**`--trail-region`** if the trail is not found in your default session region.
Organization trails may also need **`--org-id`** unless the source role can call
**`organizations:DescribeOrganization`**. Alternatively, pass the bucket explicitly:

```bash
  --bucket client-cloudtrail-logs
```

Always dry-run first — it enumerates and totals without writing anything:

```bash
ventra collect cloudtrail --mode trail --dry-run \
  --engagement-id IR-2026-0142 \
  --bucket client-cloudtrail-logs \
  --dest-bucket our-dfir-evidence \
  --start 2026-08-01 --end 2026-08-15 \
  --profile client
```

Useful flags:

- `--org-id o-abc123` — organization trails, keyed `AWSLogs/<org>/<account>/CloudTrail/…`
- `--create-dest-bucket` — provision the evidence bucket (versioned, encrypted, public access blocked)
- `--in-place` — **non-default**: catalogue the source without copying. The
  evidence stays under the client's control, where they can modify or delete it
  and we control neither retention nor immutability. The manifest records this
  explicitly. Copy is the default for a reason.

### Mode B — lookup (backfill only)

Prints a limitations banner at startup and records the same limitations in the
manifest, so an analyst who later finds no data events can tell whether that
means "none occurred" or "this mode cannot see them".

```bash
ventra collect cloudtrail \
  --mode lookup \
  --engagement-id IR-2026-0142 \
  --dest-bucket our-dfir-evidence \
  --last-days 30 \
  --regions us-east-1,us-west-2,eu-west-1 \
  --profile client --dest-profile ours \
  --window-hours 6
```

**Limits, which are the API's and not this tool's:**

- Management events only — no data events, no Insights
- 90 days maximum history
- ~2 req/sec/region × 50 events/call ≈ **100 events/sec/region**

Omit `--regions` to collect every region enabled on the account (requires
`ec2:DescribeRegions`).

Output is named to CloudTrail's own convention so listings stay legible:
`123456789012_CloudTrail_us-east-1_20260814T0600Z_00000.json.gz`

### Destination layout

```
s3://<bucket>/aws/<engagement-id>/<account-id>/<region>/<YYYY-MM-DD>/<files>
s3://<bucket>/aws/<engagement-id>/_manifests/manifest_<run-id>.json
```

`--engagement-id` is required and is validated against `[A-Za-z0-9._-]`;
slashes and `..` are rejected, because those would break the prefix isolation
that keeps one client's evidence out of another's.

### Credentials

`--profile` (source) and `--dest-profile` are separate because the client account
and our bucket are normally different credential contexts. Without a profile,
the standard boto3 chain applies (env vars, SSO, instance/task role). Both
identities are resolved and checked **before** any work starts.

Raw access keys are deliberately not accepted as CLI arguments anywhere — they
would leak into shell history and `ps` output. Use environment variables or a
credentials file.

---

## Resuming an interrupted run

Every long-running operation is resumable. State is an append-only NDJSON file
(default `./state/<engagement>-<mode>.ndjson`), fsync'd after every record, so a
kill at any instant leaves a file that is still valid — a torn final line is
detected and discarded rather than misread.

```bash
ventra collect cloudtrail --mode trail --resume \
  --engagement-id IR-2026-0142 \
  --bucket client-cloudtrail-logs \
  --dest-bucket our-dfir-evidence \
  --start 2026-08-01 --end 2026-08-15 \
  --profile client --dest-profile ours
```

- **Mode A** records completed destination keys and skips them.
- **Mode B** records per-window checkpoints and skips completed windows. An
  incomplete window restarts from its start boundary: pagination tokens expire
  after ~60 minutes and rarely survive an interruption. Chunks from the
  abandoned attempt are deleted first (the bucket is versioned, so this is
  recoverable) — otherwise a shorter retry would leave trailing objects behind
  and double-count their events at ingest.

Safety behaviours worth knowing:

- Without `--resume`, an existing state file is a **hard error**, not an
  overwrite. It may be the only record of a partial collection.
- A state file whose engagement, source bucket, or time range does not match the
  current invocation is **refused**. Resuming across those would produce an
  evidence set whose manifest does not describe its contents.

If a window keeps failing on token expiry, lower `--window-hours` so each window
completes inside the token lifetime.

---

## The manifest

One JSON manifest per run, written locally and uploaded to
`<prefix>/<engagement>/_manifests/`. It records collector version, mode, run
timestamps, source and destination, every object with size and digest, total
object and event counts, and — explicitly — every object that failed to copy and
every window that failed to pull.

The field to read first is `run.collection_complete`.

### About the hashes

Mode A copies are server-side: the bytes never reach the collector host, which
is the entire point at terabyte scale. A locally-computed SHA256 would require
downloading the whole evidence set. So `CopyObject` is called with
`ChecksumAlgorithm=SHA256` and **S3 computes the digest as it writes**, which is
then read back via `HeadObject`.

Each object records how its digest was produced, because these are not
interchangeable:

| `digest_method` | Meaning |
|---|---|
| `s3-sha256` | True whole-object SHA256, computed by S3 during the copy |
| `s3-sha256-composite` | **Multipart composite** — SHA256 of the concatenated part digests, formatted `<hex>-<parts>`. Objects over 5 GiB only. Not a whole-object hash; re-verify by recomputing with the same part size. |
| `local-sha256` | Mode B. SHA256 of the stored gzip bytes, computed while streaming — these are bytes we generate, so hashing is free and exact. |
| `none` | No digest available. The source carried no checksum and hashing it would have required egressing the object. The reason is recorded alongside. |

Single-part copies additionally compare source and destination ETags as an
independent integrity signal. Multipart copies re-chunk the object, so their
ETags legitimately differ and are not compared — comparing them would produce
false alarms.

---

## Verifying records landed in Elasticsearch

**1. Is the queue draining?**

```bash
aws sqs get-queue-attributes --queue-url "$(terraform -chdir=terraform output -raw sqs_queue_url)" \
  --attribute-names ApproximateNumberOfMessages ApproximateNumberOfMessagesNotVisible
```

**2. Did anything fail outright?** Non-zero depth here is the explicit list of
evidence that never made it in:

```bash
aws sqs get-queue-attributes --queue-url "$(terraform -chdir=terraform output -raw sqs_dlq_url)" \
  --attribute-names ApproximateNumberOfMessages
```

**3. Are documents arriving?**

```bash
curl -s -u "elastic:$ELASTIC_PASSWORD" 'localhost:9200/_cat/indices/aws-*?v&s=index'
```

**4. Did the SOF-ELK parser actually fire?** This is the check that matters —
documents can arrive looking healthy while being entirely unparsed. If
`aws.cloudtrail.event_name` is populated, `6901-aws.conf` ran:

```bash
curl -s -u "elastic:$ELASTIC_PASSWORD" -H 'Content-Type: application/json' \
  'localhost:9200/aws-*/_search?size=1' -d '{
    "query": {"exists": {"field": "aws.cloudtrail.event_name"}},
    "_source": ["@timestamp","aws.cloudtrail.event_name","aws.cloudtrail.event_source","source.ip","user.name"]
  }' | jq '.hits.hits[0]._source'
```

**5. Is the mapping right?** `source.ip` must be type `ip`, not `text`. If it is
`text`, the templates were not loaded before ingest and this index needs a
reindex:

```bash
curl -s -u "elastic:$ELASTIC_PASSWORD" 'localhost:9200/aws-*/_mapping/field/source.ip' | jq
```

**6. Did anything fail to parse?** Malformed events are quarantined rather than
dropped — silently discarding evidence is worse than storing it where someone
can look at it. This index should be empty:

```bash
curl -s -u "elastic:$ELASTIC_PASSWORD" 'localhost:9200/aws-ingest-failures-*/_count' | jq
```

**7. Cross-check against the manifest.** The event count in Elasticsearch should
match the manifest's `totals.events_collected` for a Mode B run:

```bash
jq '.totals' manifests/manifest_*.json
```

---

## Troubleshooting

**Documents in `logstash-*` instead of `aws-*`** — `[labels][type]` is not being
set to `aws`, so `1000-preprocess-all.conf` fell through to its default base
index. Check the `add_field` block in the input config.

**Documents in `aws-*` but no `aws.cloudtrail.*` fields** — `6901-aws.conf` did
not match. Almost always means the record shape reaching it is wrong: for Mode B
that the `CloudTrailEvent` envelope was not unwrapped, or that a stray
untargeted JSON parse (the superseded `0005`) left fields at the top level
instead of under `[raw]`.

**Events counted twice** — either two elasticsearch outputs are active (check
that the 9900 mount replaced SOF-ELK's rather than sitting beside it), or the
SQS visibility timeout is shorter than per-object processing time.

**`_jsonparsefail_*` tags** — the object is not what the pipeline expected.
Inspect it in `aws-ingest-failures-*`.

**Terraform replaced an existing bucket notification** — S3 permits exactly one
per bucket. See [terraform/README.md](terraform/README.md).

---

## Layout

```
collector/            the collector package
  cli.py              argument parsing, run orchestration, exit codes
  config.py           RunConfig, sessions, identity checks, bucket provisioning
  naming.py           filename convention + key layout (pure, tested)
  windows.py          time-range slicing (pure, tested)
  envelope.py         CloudTrailEvent unwrapping (pure, tested)
  manifest.py         chain-of-custody document + digest handling (tested)
  state.py            append-only resumable state (tested)
  progress.py         throughput/ETA for long sessions
  modes/trail.py      Mode A: enumerate, server-side copy, verify
  modes/lookup.py     Mode B: windows, backoff, checkpoints
  io/s3_copy.py       CopyObject / UploadPartCopy
  io/gz_ndjson_sink.py  streaming gzip NDJSON → multipart upload (tested)
tests/                125 tests, no AWS calls
terraform/            S3 → SNS → SQS + IAM
logstash/             input, preprocess, output, logstash.yml, compose override
scripts/              ES template loader
```

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Completed with no failures |
| 1 | Configuration or credential error; nothing was collected |
| 2 | Ran, but objects or windows failed — see the manifest |

Exit 2 is deliberately distinct from 0. A partial collection that looks complete
is the worst possible outcome for this tool.
