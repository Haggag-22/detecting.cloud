SELECT eventTime, userIdentity.type, userIdentity.arn, userIdentity.principalId, userIdentity.sessionContext.sessionIssuer.arn, eventName, requestParameters.cluster, requestParameters.taskDefinition, sourceIPAddress
FROM cloudtrail_logs
WHERE eventSource = 'ecs.amazonaws.com'
  AND eventName = 'RunTask'
ORDER BY eventTime DESC
