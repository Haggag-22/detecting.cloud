SELECT eventTime, userIdentity.arn, eventName, requestParameters.groupName, requestParameters.userName
FROM cloudtrail_logs
WHERE eventSource = 'iam.amazonaws.com'
  AND eventName = 'AddUserToGroup'
ORDER BY eventTime DESC
