SELECT eventTime, userIdentity.arn, eventName, requestParameters.roleName, requestParameters.userName, requestParameters.permissionsBoundary, sourceIPAddress
FROM cloudtrail_logs
WHERE eventSource = 'iam.amazonaws.com'
  AND eventName IN ('PutRolePermissionsBoundary', 'PutUserPermissionsBoundary')
ORDER BY eventTime DESC
