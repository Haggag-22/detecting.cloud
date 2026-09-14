WITH recon_evt AS (
  SELECT userIdentity.arn AS actor, eventTime AS recon_time
  FROM cloudtrail_logs
  WHERE eventSource = 'elasticbeanstalk.amazonaws.com'
    AND eventName = 'DescribeConfigurationSettings'
),
privileged_evt AS (
  SELECT userIdentity.arn AS actor, eventTime AS use_time, eventName
  FROM cloudtrail_logs
  WHERE eventName IN ('CreateAccessKey', 'AssumeRole', 'GetSecretValue', 'Decrypt')
)
SELECT r.actor, r.recon_time, p.use_time, p.eventName
FROM recon_evt r
JOIN privileged_evt p ON r.actor = p.actor
  AND p.use_time > r.recon_time
  AND p.use_time <= r.recon_time + INTERVAL '30' MINUTE
ORDER BY r.recon_time DESC
