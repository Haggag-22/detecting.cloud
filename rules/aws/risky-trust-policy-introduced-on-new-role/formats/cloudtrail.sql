SELECT eventTime, userIdentity.arn, eventName, requestParameters.roleName, requestParameters.assumeRolePolicyDocument, sourceIPAddress
FROM cloudtrail_logs
WHERE eventSource = 'iam.amazonaws.com'
  AND eventName = 'CreateRole'
ORDER BY eventTime DESC
