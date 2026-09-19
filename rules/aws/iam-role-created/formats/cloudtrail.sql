SELECT eventTime, userIdentity.arn, eventName, requestParameters.roleName, sourceIPAddress
FROM cloudtrail_logs
WHERE eventSource = 'iam.amazonaws.com'
  AND eventName = 'CreateRole'
ORDER BY eventTime DESC
