SELECT eventTime, userIdentity.arn, userIdentity.sessionContext.sessionIssuer.arn, eventName, requestParameters.projectName, sourceIPAddress
FROM cloudtrail_logs
WHERE eventSource = 'codebuild.amazonaws.com'
  AND eventName = 'StartBuild'
ORDER BY eventTime DESC
