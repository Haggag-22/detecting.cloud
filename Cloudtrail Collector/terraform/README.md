# S3 → SNS → SQS wiring

Terraform for the ingest path between the evidence bucket and the Logstash
workers, plus the IAM policies for both the workers and the collector.

## Why SQS instead of Logstash's bucket-polling S3 input

Logstash's built-in `s3` input discovers work by **listing the bucket** on an
interval and tracking what it has seen in a local `sincedb`. That model breaks
down on an evidence set, for four separate reasons:

**Listing does not scale.** `ListObjectsV2` returns 1,000 keys per call. A
bucket holding ten million objects needs ten thousand sequential calls to
enumerate once — and the polling input redoes that enumeration *every
interval*, forever, just to notice the handful of new keys. Ingest latency ends
up governed by how much history the bucket already holds. With SQS the worker
is told exactly which key arrived and does no listing at all.

**No retry semantics.** If Logstash dies while parsing an object, the polling
input's `sincedb` has usually already advanced past it. The object is never
reprocessed and nothing reports it missing. SQS only deletes a message after
the worker acknowledges it; a crash makes the message reappear after the
visibility timeout and it is processed again.

**No backpressure.** The polling input reads as fast as it can regardless of
whether Elasticsearch is keeping up. The queue is a real buffer: when workers
slow down, messages accumulate on SQS instead of being dropped, and
`ApproximateNumberOfMessages` becomes a directly observable measure of how far
behind ingest is.

**No horizontal scale, and no record of failure.** Two `s3` inputs pointed at
one bucket both read everything, duplicating every event, because the sincedb is
per-process. Any number of SQS consumers can share one queue and each message
goes to exactly one of them. And when an object genuinely cannot be parsed,
after `max_receive_count` attempts it lands in the dead-letter queue — so the
DLQ is an explicit, inspectable list of precisely which evidence failed to
ingest. That matters more here than in ordinary log pipelines: "we ingested
everything except these nine objects, and here they are" is a defensible
statement, and "ingest looked fine" is not.

## What gets created

| Resource | Purpose |
|---|---|
| `aws_sns_topic.evidence` | Fan-out point for object-created notifications |
| `aws_sqs_queue.evidence` | Work queue the Logstash workers consume |
| `aws_sqs_queue.dlq` | Dead-letter queue — the record of what failed |
| `aws_s3_bucket_notification.evidence` | `ObjectCreated:*` on the engagement prefix |
| `aws_iam_policy.logstash` | Read evidence, consume queue |
| `aws_iam_policy.collector` | Read source trail, write evidence prefix |
| `aws_s3_bucket.evidence` | Only when `create_evidence_bucket = true` |

SNS sits between S3 and SQS rather than S3 publishing to the queue directly.
The extra hop buys fan-out: S3 permits exactly **one** notification
configuration per bucket, so adding a second consumer later (a reprocessing
queue, a metrics consumer) means editing that single config and risking the
existing one. With a topic in the middle, new consumers just subscribe.

## Usage

```bash
cp terraform.tfvars.example terraform.tfvars
# edit terraform.tfvars
terraform init
terraform plan
terraform apply
```

### Bucket: create new, or attach to existing

Controlled by `create_evidence_bucket`:

```hcl
# attach to a bucket you already have (default)
evidence_bucket        = "our-dfir-evidence"
create_evidence_bucket = false
```

```hcl
# let Terraform create it, evidence-grade
evidence_bucket            = "our-dfir-evidence"
create_evidence_bucket     = true
enable_object_lock         = true
object_lock_mode           = "GOVERNANCE"
object_lock_retention_days = 2555
```

The collector has the matching flag — `--create-dest-bucket` — for the case
where you want the bucket provisioned at collection time instead.

## Things that will bite you

**S3 allows one notification configuration per bucket.** Applying this to a
bucket that already has notifications defined — by another Terraform state, by
ClickOps, by another tool — **replaces them silently**. Check first:

```bash
aws s3api get-bucket-notification-configuration --bucket our-dfir-evidence
```

**Object Lock is creation-time only and permanent.** It cannot be enabled on an
existing bucket and cannot be disabled afterwards. `COMPLIANCE` mode means
nobody — not you, not the root account, not AWS support — can delete an object
before its retention expires. Be certain about the retention period before
choosing it. `GOVERNANCE` is the safer default and still blocks accidental
deletion.

**Visibility timeout must exceed per-object processing time.** Default is 900s,
sized for the collector's default 256 MB uncompressed chunks. If you raise
`--chunk-size-mb`, raise `visibility_timeout_seconds` to match — otherwise the
message reappears while Logstash is still working on it and the object is
ingested twice, producing duplicate events with no error anywhere.

**`raw_message_delivery` is a matched pair with the Logstash input.** The
subscription sets it `true`, so the queue carries bare S3 event JSON; the input
config sets `from_sns => false` to match. Changing one without the other makes
every message fail to parse.

**The notification filters on the `.json.gz` suffix.** Run manifests are written
to `<prefix>/<engagement>/_manifests/manifest_*.json`, which is *inside* the
notified prefix. Without that suffix filter, every manifest would be queued and
Logstash would try to parse a chain-of-custody document as CloudTrail.

**IAM policies are created but only auto-attached to roles.** ARNs in
`logstash_principal_arns` / `collector_principal_arns` that are roles get the
policy attached; user ARNs do not, and must be attached manually. The
non-exclusive `aws_iam_role_policy_attachment` is used deliberately —
`aws_iam_policy_attachment` manages a policy's entire attachment list and would
detach it from any role outside this state.

## Verifying

```bash
# queue depth — should drain toward zero while ingest runs
aws sqs get-queue-attributes --queue-url "$(terraform output -raw sqs_queue_url)" \
  --attribute-names ApproximateNumberOfMessages ApproximateNumberOfMessagesNotVisible
```

```bash
# DLQ depth — anything above zero means evidence failed to ingest
aws sqs get-queue-attributes --queue-url "$(terraform output -raw sqs_dlq_url)" \
  --attribute-names ApproximateNumberOfMessages
```

End-to-end check — put a file in the prefix and watch the queue depth rise:

```bash
echo '{"Records":[]}' | gzip > /tmp/probe.json.gz
aws s3 cp /tmp/probe.json.gz "s3://$(terraform output -raw evidence_bucket)/$(terraform output -raw evidence_prefix)probe.json.gz"
```
