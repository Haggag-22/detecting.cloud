WITH boundary_change AS (
  SELECT userIdentity.arn AS actor, eventTime AS change_time
  FROM cloudtrail_logs
  WHERE eventSource = 'iam.amazonaws.com'
    AND eventName IN ('PutRolePermissionsBoundary', 'PutUserPermissionsBoundary')
),
sensitive_use AS (
  SELECT userIdentity.arn AS actor, eventTime AS use_time, eventName
  FROM cloudtrail_logs
  WHERE eventName IN ('AssumeRole', 'CreatePolicyVersion', 'SetDefaultPolicyVersion', 'PassRole', 'GetSecretValue', 'Decrypt')
)
SELECT b.actor, b.change_time, s.use_time, s.eventName
FROM boundary_change b
JOIN sensitive_use s ON b.actor = s.actor
  AND s.use_time > b.change_time
  AND s.use_time <= b.change_time + INTERVAL '15' MINUTE
ORDER BY b.change_time DESC
