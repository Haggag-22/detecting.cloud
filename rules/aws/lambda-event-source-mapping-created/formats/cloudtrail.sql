SELECT eventTime, userIdentity.type, userIdentity.arn, requestParameters.functionName, requestParameters.eventSourceArn, requestParameters.enabled, requestParameters.batchSize, sourceIPAddress
FROM cloudtrail_logs
WHERE eventSource = 'lambda.amazonaws.com'
  AND eventName = 'CreateEventSourceMapping'
ORDER BY eventTime DESC
