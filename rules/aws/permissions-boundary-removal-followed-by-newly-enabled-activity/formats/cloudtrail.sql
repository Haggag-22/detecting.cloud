WITH boundary_removal AS (
  SELECT userIdentity.arn AS actor, eventTime AS removal_time
  FROM cloudtrail_logs
  WHERE eventSource = 'iam.amazonaws.com'
    AND eventName IN ('DeleteRolePermissionsBoundary', 'DeleteUserPermissionsBoundary')
),
sensitive_use AS (
  SELECT userIdentity.arn AS actor, eventTime AS use_time, eventName
  FROM cloudtrail_logs
  WHERE eventName IN ('AssumeRole', 'CreateAccessKey', 'AttachUserPolicy', 'AttachRolePolicy', 'PutUserPolicy', 'PutRolePolicy', 'GetSecretValue', 'Decrypt')
)
SELECT b.actor, b.removal_time, s.use_time, s.eventName
FROM boundary_removal b
JOIN sensitive_use s ON b.actor = s.actor
  AND s.use_time > b.removal_time
  AND s.use_time <= b.removal_time + INTERVAL '15' MINUTE
ORDER BY b.removal_time DESC
