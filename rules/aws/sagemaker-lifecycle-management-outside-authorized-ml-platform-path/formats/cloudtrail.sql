SELECT eventTime, userIdentity.type, userIdentity.arn, userIdentity.sessionContext.sessionIssuer.arn, eventName, requestParameters.notebookInstanceLifecycleConfigName, requestParameters.notebookInstanceName, requestParameters.lifecycleConfigName, sourceIPAddress
FROM cloudtrail_logs
WHERE eventSource = 'sagemaker.amazonaws.com'
  AND eventName IN ('CreateNotebookInstanceLifecycleConfig', 'UpdateNotebookInstanceLifecycleConfig', 'CreateNotebookInstance', 'UpdateNotebookInstance')
ORDER BY eventTime DESC
