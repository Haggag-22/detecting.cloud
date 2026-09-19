SELECT eventTime, userIdentity.type, userIdentity.arn, requestParameters.tableName, sourceIPAddress
FROM cloudtrail_logs
WHERE eventSource = 'dynamodb.amazonaws.com'
  AND eventName = 'UpdateTable'
  AND requestParameters.deletionProtectionEnabled = false
ORDER BY eventTime DESC
