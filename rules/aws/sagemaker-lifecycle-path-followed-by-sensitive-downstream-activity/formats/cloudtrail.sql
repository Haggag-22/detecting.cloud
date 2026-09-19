WITH sagemaker_evt AS (
  SELECT userIdentity.arn AS actor, eventTime AS sm_time
  FROM cloudtrail_logs
  WHERE eventSource = 'sagemaker.amazonaws.com'
    AND eventName IN ('UpdateNotebookInstance', 'StartNotebookInstance')
),
sensitive_evt AS (
  SELECT userIdentity.arn AS actor, eventTime AS use_time, eventName
  FROM cloudtrail_logs
  WHERE eventName IN ('GetSecretValue', 'Decrypt', 'AssumeRole', 'CreateAccessKey', 'PutUserPolicy', 'AttachRolePolicy')
)
SELECT s.actor, s.sm_time, e.use_time, e.eventName
FROM sagemaker_evt s
JOIN sensitive_evt e ON s.actor = e.actor
  AND e.use_time > s.sm_time
  AND e.use_time <= s.sm_time + INTERVAL '30' MINUTE
ORDER BY s.sm_time DESC
