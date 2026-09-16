terraform {
  required_version = ">= 1.5"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

locals {
  name = "ct-evidence-${var.engagement_id}"

  # Trailing slash matters: "aws" would also match "aws-staging/...".
  notification_prefix = "${trim(var.evidence_prefix, "/")}/${var.engagement_id}/"

  bucket_arn = var.create_evidence_bucket ? aws_s3_bucket.evidence[0].arn : "arn:${data.aws_partition.current.partition}:s3:::${var.evidence_bucket}"
  bucket_id  = var.create_evidence_bucket ? aws_s3_bucket.evidence[0].id : var.evidence_bucket

  tags = merge(var.tags, {
    EngagementId = var.engagement_id
    ManagedBy    = "terraform"
    Purpose      = "dfir-cloudtrail-evidence"
  })
}

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}
data "aws_region" "current" {}

# ---------------------------------------------------------------------------
# Evidence bucket (optional)
# ---------------------------------------------------------------------------

resource "aws_s3_bucket" "evidence" {
  count = var.create_evidence_bucket ? 1 : 0

  bucket = var.evidence_bucket
  tags   = local.tags

  # Object Lock is only settable at creation and can never be removed.
  object_lock_enabled = var.enable_object_lock

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_s3_bucket_versioning" "evidence" {
  count = var.create_evidence_bucket ? 1 : 0

  bucket = aws_s3_bucket.evidence[0].id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "evidence" {
  count = var.create_evidence_bucket ? 1 : 0

  bucket = aws_s3_bucket.evidence[0].id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "evidence" {
  count = var.create_evidence_bucket ? 1 : 0

  bucket = aws_s3_bucket.evidence[0].id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_object_lock_configuration" "evidence" {
  count = var.create_evidence_bucket && var.enable_object_lock ? 1 : 0

  bucket = aws_s3_bucket.evidence[0].id

  rule {
    default_retention {
      mode = var.object_lock_mode
      days = var.object_lock_retention_days
    }
  }

  depends_on = [aws_s3_bucket_versioning.evidence]
}

# Multipart uploads abandoned by an interrupted collector run are invisible in
# the console but still billable. The collector aborts its own on failure; this
# catches the cases where it was killed before it could.
resource "aws_s3_bucket_lifecycle_configuration" "evidence" {
  count = var.create_evidence_bucket ? 1 : 0

  bucket = aws_s3_bucket.evidence[0].id

  rule {
    id     = "abort-incomplete-multipart-uploads"
    status = "Enabled"

    filter {}

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}
