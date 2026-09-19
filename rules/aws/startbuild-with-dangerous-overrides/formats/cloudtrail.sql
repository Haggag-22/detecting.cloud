SELECT eventTime, userIdentity.arn, eventName, requestParameters.projectName, requestParameters.buildspecOverride, requestParameters.environmentVariablesOverride, sourceIPAddress
FROM cloudtrail_logs
WHERE eventSource = 'codebuild.amazonaws.com'
  AND eventName = 'StartBuild'
  AND (requestParameters.buildspecOverride IS NOT NULL OR requestParameters.environmentVariablesOverride IS NOT NULL)
ORDER BY eventTime DESC
