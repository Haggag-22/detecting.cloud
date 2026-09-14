WITH start_evt AS (
  SELECT userIdentity.arn AS actor, eventTime AS start_time
  FROM cloudtrail_logs
  WHERE eventSource = 'codebuild.amazonaws.com'
    AND eventName = 'StartBuild'
    AND (requestParameters.buildspecOverride IS NOT NULL OR requestParameters.environmentVariablesOverride IS NOT NULL)
),
sensitive_evt AS (
  SELECT userIdentity.arn AS actor, eventTime AS use_time, eventName
  FROM cloudtrail_logs
  WHERE eventName IN ('GetSecretValue', 'CreateAccessKey', 'AssumeRole', 'Decrypt')
)
SELECT s.actor, s.start_time, e.use_time, e.eventName
FROM start_evt s
JOIN sensitive_evt e ON s.actor = e.actor
  AND e.use_time > s.start_time
  AND e.use_time <= s.start_time + INTERVAL '30' MINUTE
ORDER BY s.start_time DESC
