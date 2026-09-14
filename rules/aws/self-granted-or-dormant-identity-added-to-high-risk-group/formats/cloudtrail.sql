SELECT eventTime, userIdentity.arn, eventName, requestParameters.groupName, requestParameters.userName
FROM cloudtrail_logs
WHERE eventSource = 'iam.amazonaws.com'
  AND eventName = 'AddUserToGroup'
  AND (requestParameters.userName LIKE '%backup%' OR requestParameters.userName LIKE '%svc%' OR requestParameters.userName LIKE '%admin2%' OR requestParameters.userName LIKE '%support-temp%' OR requestParameters.userName LIKE '%breakglass2%' OR requestParameters.userName LIKE '%automation-backup%'
    OR regexp_extract(userIdentity.arn, 'user/([^/]+)$', 1) = requestParameters.userName)
ORDER BY eventTime DESC
