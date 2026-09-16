output "evidence_bucket" {
  value       = local.bucket_id
  description = "Evidence bucket name. Pass to the collector as --dest-bucket."
}

output "evidence_prefix" {
  value       = local.notification_prefix
  description = "Notified prefix. The collector must write here (--dest-prefix + --engagement-id)."
}

output "sqs_queue_url" {
  value       = aws_sqs_queue.evidence.url
  description = "Ingest queue URL. Set as SQS_QUEUE_URL for the Logstash input."
}

output "sqs_queue_arn" {
  value       = aws_sqs_queue.evidence.arn
  description = "Ingest queue ARN."
}

output "sqs_dlq_url" {
  value       = aws_sqs_queue.dlq.url
  description = "Dead-letter queue URL. A non-zero depth here means objects failed to ingest."
}

output "sns_topic_arn" {
  value       = aws_sns_topic.evidence.arn
  description = "Notification topic. Subscribe additional consumers here rather than editing the bucket notification."
}

output "logstash_policy_arn" {
  value       = aws_iam_policy.logstash.arn
  description = "Attach to the Logstash workers' role."
}

output "collector_policy_arn" {
  value       = aws_iam_policy.collector.arn
  description = "Attach to the role the collector runs as."
}

output "collector_command" {
  description = "Collector invocation matching this deployment."
  value       = <<-EOT
    python -m collector \
      --mode trail \
      --engagement-id ${var.engagement_id} \
      --bucket <client-trail-bucket> \
      --dest-bucket ${local.bucket_id} \
      --dest-prefix ${trim(var.evidence_prefix, "/")} \
      --start <YYYY-MM-DD> --end <YYYY-MM-DD> \
      --profile client --dest-profile ours
  EOT
}

output "verify_queue_command" {
  description = "Check queue depth and DLQ depth."
  value       = <<-EOT
    aws sqs get-queue-attributes --queue-url ${aws_sqs_queue.evidence.url} \
      --attribute-names ApproximateNumberOfMessages ApproximateNumberOfMessagesNotVisible
    aws sqs get-queue-attributes --queue-url ${aws_sqs_queue.dlq.url} \
      --attribute-names ApproximateNumberOfMessages
  EOT
}
