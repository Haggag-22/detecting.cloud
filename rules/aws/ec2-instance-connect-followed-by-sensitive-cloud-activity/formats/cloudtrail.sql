WITH push_evt AS (
  SELECT userIdentity.arn AS actor, eventTime AS push_time
  FROM cloudtrail_logs
  WHERE eventSource = 'ec2-instance-connect.amazonaws.com'
    AND eventName = 'SendSSHPublicKey'
),
sensitive_evt AS (
  SELECT userIdentity.arn AS actor, eventTime AS use_time, eventName
  FROM cloudtrail_logs
  WHERE eventName IN ('StartSession', 'GetSecretValue', 'Decrypt', 'AssumeRole', 'CreateAccessKey', 'PutUserPolicy', 'AttachRolePolicy', 'PutRolePolicy')
)
SELECT e.actor, e.push_time, s.use_time, s.eventName
FROM push_evt e
JOIN sensitive_evt s ON e.actor = s.actor
  AND s.use_time > e.push_time
  AND s.use_time <= e.push_time + INTERVAL '15' MINUTE
ORDER BY e.push_time DESC
