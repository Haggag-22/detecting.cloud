WITH config_evt AS (
  SELECT userIdentity.arn AS actor, eventTime AS config_time, requestParameters.notebookInstanceName AS notebook_name, requestParameters.lifecycleConfigName AS lifecycle_name, requestParameters.notebookInstanceLifecycleConfigName AS config_name
  FROM cloudtrail_logs
  WHERE eventSource = 'sagemaker.amazonaws.com'
    AND eventName IN ('CreateNotebookInstanceLifecycleConfig', 'UpdateNotebookInstanceLifecycleConfig', 'UpdateNotebookInstance')
),
start_evt AS (
  SELECT userIdentity.arn AS actor, eventTime AS start_time, requestParameters.notebookInstanceName
  FROM cloudtrail_logs
  WHERE eventSource = 'sagemaker.amazonaws.com'
    AND eventName = 'StartNotebookInstance'
)
SELECT c.actor, c.config_time, c.notebook_name, c.lifecycle_name, c.config_name, s.start_time, s.notebookInstanceName
FROM config_evt c
JOIN start_evt s ON c.actor = s.actor
  AND s.start_time > c.config_time
  AND s.start_time <= c.config_time + INTERVAL '30' MINUTE
ORDER BY c.config_time DESC
