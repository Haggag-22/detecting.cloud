SELECT eventTime, userIdentity.arn, eventName, requestParameters.cluster, requestParameters.taskDefinition, requestParameters.overrides, sourceIPAddress
FROM cloudtrail_logs
WHERE eventSource = 'ecs.amazonaws.com'
  AND eventName = 'RunTask'
ORDER BY eventTime DESC
