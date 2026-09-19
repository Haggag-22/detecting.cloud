SELECT eventTime, userIdentity.type, userIdentity.arn, userIdentity.sessionContext.sessionIssuer.arn, eventName, requestParameters.roleName, requestParameters.userName, requestParameters.policyArn, sourceIPAddress
FROM cloudtrail_logs
WHERE eventSource = 'iam.amazonaws.com'
  AND eventName IN ('DetachUserPolicy', 'DetachRolePolicy', 'DeleteUserPolicy', 'DeleteRolePolicy')
ORDER BY eventTime DESC
