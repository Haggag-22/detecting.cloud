variable "engagement_id" {
  type        = string
  description = "Engagement identifier. Forms the prefix that isolates this client's evidence."

  validation {
    # Same charset the collector enforces. A slash or '..' here would break
    # per-engagement prefix isolation.
    condition     = can(regex("^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$", var.engagement_id))
    error_message = "engagement_id must be 1-64 chars of [A-Za-z0-9._-] starting alphanumeric."
  }
}

variable "evidence_bucket" {
  type        = string
  description = "Name of the evidence bucket."
}

variable "create_evidence_bucket" {
  type        = bool
  default     = false
  description = <<-EOT
    Create the evidence bucket, or attach to one that already exists.

    false (default) attaches to an existing bucket and manages only the
    notification, topic, queues, and IAM. true additionally creates the bucket
    with versioning, SSE, and public access blocked.

    Note: S3 allows exactly ONE notification configuration per bucket. Pointing
    this at a bucket that already has notifications defined elsewhere will
    silently replace them. See README.
  EOT
}

variable "evidence_prefix" {
  type        = string
  default     = "aws"
  description = "Root prefix inside the bucket. Must match the collector's --dest-prefix."
}

variable "enable_object_lock" {
  type        = bool
  default     = false
  description = <<-EOT
    Enable S3 Object Lock on a newly created bucket (create_evidence_bucket only).

    Object Lock can ONLY be enabled at bucket creation time and cannot be turned
    off afterwards. In COMPLIANCE mode, objects cannot be deleted or altered by
    anyone, including the root account, until retention expires.
  EOT
}

variable "object_lock_retention_days" {
  type        = number
  default     = 2555 # ~7 years
  description = "Default Object Lock retention in days, when enable_object_lock is true."
}

variable "object_lock_mode" {
  type        = string
  default     = "GOVERNANCE"
  description = <<-EOT
    GOVERNANCE (default) allows users holding s3:BypassGovernanceRetention to
    delete early; COMPLIANCE allows nobody to, ever, until retention expires.
    Choose COMPLIANCE only when you are certain about the retention period.
  EOT

  validation {
    condition     = contains(["GOVERNANCE", "COMPLIANCE"], var.object_lock_mode)
    error_message = "object_lock_mode must be GOVERNANCE or COMPLIANCE."
  }
}

variable "visibility_timeout_seconds" {
  type        = number
  default     = 900
  description = <<-EOT
    SQS visibility timeout. Must exceed the time Logstash needs to fully process
    the largest single object, or the message reappears mid-processing and the
    object is ingested twice.

    900s suits the collector's default 256 MB uncompressed chunks. Raise it if
    you raise --chunk-size-mb.
  EOT
}

variable "max_receive_count" {
  type        = number
  default     = 5
  description = "Deliveries attempted before a message is moved to the DLQ."
}

variable "message_retention_seconds" {
  type        = number
  default     = 1209600 # 14 days, the SQS maximum
  description = "How long an unprocessed message survives. Max (14d) by default so a weekend outage does not lose evidence."
}

variable "logstash_principal_arns" {
  type        = list(string)
  default     = []
  description = <<-EOT
    IAM role/user ARNs for the Logstash workers. When set, the queue and bucket
    policies are scoped to these principals. When empty, the managed IAM policy
    is still created for you to attach, but no resource policy is written.
  EOT
}

variable "collector_principal_arns" {
  type        = list(string)
  default     = []
  description = "IAM role/user ARNs the collector runs as."
}

variable "source_trail_bucket" {
  type        = string
  default     = ""
  description = "Client trail bucket the collector reads in mode trail. Used to scope the collector's read policy."
}

variable "tags" {
  type        = map(string)
  default     = {}
  description = "Tags applied to every resource."
}
