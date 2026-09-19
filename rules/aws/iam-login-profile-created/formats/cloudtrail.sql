SELECT eventTime, userIdentity.arn, eventName, requestParameters.userName, sourceIPAddress
FROM cloudtrail_logs
WHERE eventSource = 'iam.amazonaws.com'
  AND eventName = 'CreateLoginProfile'
ORDER BY eventTime DESC
