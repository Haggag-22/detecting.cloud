SELECT eventTime, userIdentity.arn, eventName, requestParameters.roleName, requestParameters.userName, requestParameters.policyArn, requestParameters.policyName
FROM cloudtrail_logs
WHERE eventSource = 'iam.amazonaws.com'
  AND eventName IN ('DetachUserPolicy', 'DetachRolePolicy', 'DeleteUserPolicy', 'DeleteRolePolicy')
ORDER BY eventTime DESC
