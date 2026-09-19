SELECT eventTime, userIdentity.arn, eventName, requestParameters.notebookInstanceName, requestParameters.lifecycleConfigName, sourceIPAddress
FROM cloudtrail_logs
WHERE eventSource = 'sagemaker.amazonaws.com'
  AND eventName IN ('CreateNotebookInstance', 'UpdateNotebookInstance')
  AND requestParameters.lifecycleConfigName IS NOT NULL
  AND requestParameters.lifecycleConfigName != ''
ORDER BY eventTime DESC
