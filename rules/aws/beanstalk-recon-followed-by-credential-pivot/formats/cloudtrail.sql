WITH recon_evt AS (
  SELECT userIdentity.arn AS actor, eventTime AS recon_time
  FROM cloudtrail_logs
  WHERE eventSource = 'elasticbeanstalk.amazonaws.com'
    AND eventName = 'DescribeConfigurationSettings'
),
pivot_evt AS (
  SELECT userIdentity.arn AS actor, eventTime AS pivot_time, eventName
  FROM cloudtrail_logs
  WHERE eventName IN ('CreateAccessKey', 'AssumeRole', 'AttachUserPolicy', 'PutUserPolicy', 'AttachRolePolicy')
)
SELECT r.actor, r.recon_time, p.pivot_time, p.eventName
FROM recon_evt r
JOIN pivot_evt p ON r.actor = p.actor
  AND p.pivot_time > r.recon_time
  AND p.pivot_time <= r.recon_time + INTERVAL '30' MINUTE
ORDER BY r.recon_time DESC
