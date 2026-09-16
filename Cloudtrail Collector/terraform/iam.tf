# ---------------------------------------------------------------------------
# IAM for the Logstash workers
#
# Read the evidence, consume the queue, nothing else. Notably absent:
# s3:PutObject and s3:DeleteObject. The ingest path has no business writing to
# an evidence bucket, and withholding the permission is what makes that
# structural rather than a matter of trust.
# ---------------------------------------------------------------------------

data "aws_iam_policy_document" "logstash" {
  statement {
    sid    = "ReadEvidenceObjects"
    effect = "Allow"

    actions = [
      "s3:GetObject",
      "s3:GetObjectVersion",
    ]

    resources = ["${local.bucket_arn}/${local.notification_prefix}*"]
  }

  statement {
    sid    = "ListEvidencePrefix"
    effect = "Allow"

    actions   = ["s3:ListBucket"]
    resources = [local.bucket_arn]

    # Scoped so these credentials cannot enumerate other engagements in the
    # same bucket.
    condition {
      test     = "StringLike"
      variable = "s3:prefix"
      values   = ["${local.notification_prefix}*"]
    }
  }

  statement {
    sid    = "ConsumeIngestQueue"
    effect = "Allow"

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

resource "aws_iam_policy" "logstash" {
  name        = "${local.name}-logstash"
  description = "Logstash workers: read evidence objects and consume the ingest queue."
  policy      = data.aws_iam_policy_document.logstash.json
  tags        = local.tags
}

# ---------------------------------------------------------------------------
# IAM for the collector
#
# Read the source trail bucket, write the evidence prefix. The multipart and
# checksum actions are required for large-object copies and for the manifest's
# SHA256 to exist at all.
# ---------------------------------------------------------------------------

data "aws_iam_policy_document" "collector" {
  statement {
    sid    = "WriteEvidence"
    effect = "Allow"

    actions = [
      "s3:PutObject",
      # Needed for the SHA256 that the manifest records. Without
      # GetObjectAttributes, the collector cannot read back the checksum S3
      # computed during the copy.
      "s3:GetObject",
      "s3:GetObjectAttributes",
      "s3:AbortMultipartUpload",
      "s3:ListMultipartUploadParts",
    ]

    resources = ["${local.bucket_arn}/${trim(var.evidence_prefix, "/")}/*"]
  }

  statement {
    sid    = "InspectEvidenceBucket"
    effect = "Allow"

    actions = [
      "s3:ListBucket",
      "s3:ListBucketMultipartUploads",
      "s3:GetBucketLocation",
    ]

    resources = [local.bucket_arn]
  }

  statement {
    sid    = "DiscoverRegions"
    effect = "Allow"

    # Mode B defaults to every enabled region; without this the collector
    # cannot tell which those are and would have to be told explicitly.
    actions   = ["ec2:DescribeRegions"]
    resources = ["*"]
  }

  statement {
    sid    = "LookupEvents"
    effect = "Allow"

    actions = [
      "cloudtrail:LookupEvents",
      "cloudtrail:DescribeTrails",
      "cloudtrail:GetTrailStatus",
    ]

    resources = ["*"]
  }

  dynamic "statement" {
    for_each = var.source_trail_bucket != "" ? [1] : []

    content {
      sid    = "ReadSourceTrail"
      effect = "Allow"

      actions = [
        "s3:GetObject",
        "s3:GetObjectVersion",
        "s3:GetObjectAttributes",
      ]

      resources = ["arn:${data.aws_partition.current.partition}:s3:::${var.source_trail_bucket}/*"]
    }
  }

  dynamic "statement" {
    for_each = var.source_trail_bucket != "" ? [1] : []

    content {
      sid    = "ListSourceTrail"
      effect = "Allow"

      actions = [
        "s3:ListBucket",
        "s3:GetBucketLocation",
      ]

      resources = ["arn:${data.aws_partition.current.partition}:s3:::${var.source_trail_bucket}"]
    }
  }
}

resource "aws_iam_policy" "collector" {
  name        = "${local.name}-collector"
  description = "Collector: read the source trail, write the evidence prefix."
  policy      = data.aws_iam_policy_document.collector.json
  tags        = local.tags
}

# Attachments use the non-exclusive resource. aws_iam_policy_attachment would
# manage the policy's attachment list as a whole and silently detach it from any
# role Terraform does not know about.
#
# Only role ARNs are attached here; user ARNs are left to be attached manually,
# since Logstash workers should be running as a role.
locals {
  logstash_role_names = [
    for arn in var.logstash_principal_arns :
    reverse(split("/", arn))[0]
    if can(regex(":role/", arn))
  ]

  collector_role_names = [
    for arn in var.collector_principal_arns :
    reverse(split("/", arn))[0]
    if can(regex(":role/", arn))
  ]
}

resource "aws_iam_role_policy_attachment" "logstash" {
  for_each = toset(local.logstash_role_names)

  role       = each.value
  policy_arn = aws_iam_policy.logstash.arn
}

resource "aws_iam_role_policy_attachment" "collector" {
  for_each = toset(local.collector_role_names)

  role       = each.value
  policy_arn = aws_iam_policy.collector.arn
}
