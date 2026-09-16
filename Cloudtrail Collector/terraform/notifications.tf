# ---------------------------------------------------------------------------
# S3 ObjectCreated:* -> SNS -> SQS -> Logstash
#
# SNS sits between S3 and SQS rather than S3 publishing to SQS directly. It
# costs one extra hop and buys fan-out: a second queue for a parallel reprocess,
# a metrics consumer, or an alerting subscriber can be attached later without
# touching the bucket's notification config (of which S3 permits exactly one).
# ---------------------------------------------------------------------------

resource "aws_sns_topic" "evidence" {
  name = "${local.name}-notify"
  tags = local.tags
}

data "aws_iam_policy_document" "sns_topic" {
  # Only this bucket, and only from our own account, may publish.
  statement {
    sid    = "AllowS3Publish"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["s3.amazonaws.com"]
    }

    actions   = ["SNS:Publish"]
    resources = [aws_sns_topic.evidence.arn]

    condition {
      test     = "ArnLike"
      variable = "aws:SourceArn"
      values   = [local.bucket_arn]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }
}

resource "aws_sns_topic_policy" "evidence" {
  arn    = aws_sns_topic.evidence.arn
  policy = data.aws_iam_policy_document.sns_topic.json
}

# ---------------------------------------------------------------------------
# Queues
# ---------------------------------------------------------------------------

resource "aws_sqs_queue" "dlq" {
  name = "${local.name}-dlq"

  # Failures must outlive the weekend they happen on: the DLQ is the record of
  # exactly which objects never made it into Elasticsearch.
  message_retention_seconds = var.message_retention_seconds
  sqs_managed_sse_enabled   = true

  tags = local.tags
}

resource "aws_sqs_queue" "evidence" {
  name = "${local.name}-ingest"

  # Must exceed the time Logstash needs for the largest single object, or the
  # message reappears mid-processing and the object is ingested twice.
  visibility_timeout_seconds = var.visibility_timeout_seconds
  message_retention_seconds  = var.message_retention_seconds
  sqs_managed_sse_enabled    = true

  # Long polling: fewer empty receives, lower cost, lower latency.
  receive_wait_time_seconds = 20

  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.dlq.arn
    maxReceiveCount     = var.max_receive_count
  })

  tags = local.tags
}

data "aws_iam_policy_document" "queue" {
  statement {
    sid    = "AllowSNSDeliver"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["sns.amazonaws.com"]
    }

    actions   = ["sqs:SendMessage"]
    resources = [aws_sqs_queue.evidence.arn]

    condition {
      test     = "ArnEquals"
      variable = "aws:SourceArn"
      values   = [aws_sns_topic.evidence.arn]
    }
  }

  dynamic "statement" {
    for_each = length(var.logstash_principal_arns) > 0 ? [1] : []

    content {
      sid    = "AllowLogstashConsume"
      effect = "Allow"

      principals {
        type        = "AWS"
        identifiers = var.logstash_principal_arns
      }

      actions = [
        "sqs:ReceiveMessage",
        "sqs:DeleteMessage",
        "sqs:GetQueueAttributes",
        "sqs:GetQueueUrl",
        "sqs:ChangeMessageVisibility",
      ]

      resources = [aws_sqs_queue.evidence.arn]
    }
  }
}

resource "aws_sqs_queue_policy" "evidence" {
  queue_url = aws_sqs_queue.evidence.id
  policy    = data.aws_iam_policy_document.queue.json
}

# raw_message_delivery strips the SNS envelope so the queue carries the S3 event
# JSON directly. The Logstash input is configured with `from_sns => false` to
# match. Flipping one without the other means every message fails to parse.
resource "aws_sns_topic_subscription" "evidence" {
  topic_arn            = aws_sns_topic.evidence.arn
  protocol             = "sqs"
  endpoint             = aws_sqs_queue.evidence.arn
  raw_message_delivery = true
}

# ---------------------------------------------------------------------------
# Bucket notification
# ---------------------------------------------------------------------------

# WARNING: S3 supports exactly one notification configuration per bucket.
# Applying this to a bucket that already has notifications REPLACES them.
resource "aws_s3_bucket_notification" "evidence" {
  bucket = local.bucket_id

  topic {
    topic_arn = aws_sns_topic.evidence.arn
    events    = ["s3:ObjectCreated:*"]

    filter_prefix = local.notification_prefix

    # Data objects only. Run manifests are written to
    # <prefix>/<engagement>/_manifests/manifest_*.json, which is inside the
    # prefix above; without this suffix filter every manifest would be queued
    # and Logstash would try to parse a chain-of-custody document as CloudTrail.
    filter_suffix = ".json.gz"
  }

  depends_on = [aws_sns_topic_policy.evidence]
}
