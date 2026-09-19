WITH ssm_start AS (
  SELECT userIdentity.arn AS actor, eventTime AS start_time
  FROM cloudtrail_logs
  WHERE eventSource = 'ssm.amazonaws.com'
    AND eventName = 'StartSession'
),
sensitive_use AS (
  SELECT userIdentity.arn AS actor, eventTime AS use_time, eventName
  FROM cloudtrail_logs
  WHERE eventName IN ('GetSecretValue', 'Decrypt', 'AssumeRole', 'CreateAccessKey', 'PutUserPolicy', 'AttachRolePolicy', 'PutRolePolicy', 'CreateSnapshot', 'CreateSnapshots')
)
SELECT e.actor, e.start_time, s.use_time, s.eventName
FROM ssm_start e
JOIN sensitive_use s ON e.actor = s.actor
  AND s.use_time > e.start_time
  AND s.use_time <= e.start_time + INTERVAL '15' MINUTE
ORDER BY e.start_time DESC
