SELECT eventTime, userIdentity.arn, eventName, requestParameters.roleName, requestParameters.userName, sourceIPAddress
FROM cloudtrail_logs
WHERE eventSource = 'iam.amazonaws.com'
  AND eventName IN ('PutRolePolicy', 'PutUserPolicy')
ORDER BY eventTime DESC
