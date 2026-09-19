SELECT eventTime, userIdentity.arn, eventName, requestParameters.userName
FROM cloudtrail_logs
WHERE eventSource = 'iam.amazonaws.com'
  AND eventName = 'UpdateLoginProfile'
ORDER BY eventTime DESC
