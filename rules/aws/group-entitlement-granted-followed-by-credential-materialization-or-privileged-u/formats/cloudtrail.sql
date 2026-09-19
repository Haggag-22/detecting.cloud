WITH add_event AS (
  SELECT requestParameters.userName AS target_user, eventTime AS add_time
  FROM cloudtrail_logs
  WHERE eventSource = 'iam.amazonaws.com'
    AND eventName = 'AddUserToGroup'
),
sensitive_use AS (
  SELECT regexp_extract(userIdentity.arn, 'user/([^/]+)$', 1) AS target_user, eventTime AS use_time, eventName
  FROM cloudtrail_logs
  WHERE eventName IN ('CreateAccessKey', 'AssumeRole', 'GetSecretValue', 'AttachUserPolicy', 'PutUserPolicy', 'ConsoleLogin')
)
SELECT a.target_user, a.add_time, s.use_time, s.eventName
FROM add_event a
JOIN sensitive_use s ON a.target_user = s.target_user
  AND s.use_time > a.add_time
  AND s.use_time <= a.add_time + INTERVAL '15' MINUTE
ORDER BY a.add_time DESC
