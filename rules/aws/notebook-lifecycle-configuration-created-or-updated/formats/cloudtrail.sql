SELECT eventTime, userIdentity.arn, eventName, requestParameters.notebookInstanceLifecycleConfigName, sourceIPAddress
FROM cloudtrail_logs
WHERE eventSource = 'sagemaker.amazonaws.com'
  AND eventName IN ('CreateNotebookInstanceLifecycleConfig', 'UpdateNotebookInstanceLifecycleConfig')
ORDER BY eventTime DESC
