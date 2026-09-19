WITH ecs_run AS (
  SELECT userIdentity.arn AS actor, eventTime AS run_time
  FROM cloudtrail_logs
  WHERE eventSource = 'ecs.amazonaws.com'
    AND eventName = 'RunTask'
),
sensitive_use AS (
  SELECT userIdentity.arn AS actor, eventTime AS use_time, eventName
  FROM cloudtrail_logs
  WHERE eventName IN ('AssumeRole', 'GetSecretValue', 'AttachRolePolicy', 'PutRolePolicy', 'RegisterTaskDefinition')
)
SELECT e.actor, e.run_time, s.use_time, s.eventName
FROM ecs_run e
JOIN sensitive_use s ON e.actor = s.actor
  AND s.use_time > e.run_time
  AND s.use_time <= e.run_time + INTERVAL '15' MINUTE
ORDER BY e.run_time DESC
