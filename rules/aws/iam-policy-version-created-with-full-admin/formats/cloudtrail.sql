SELECT eventTime, userIdentity.type, userIdentity.arn, requestParameters.policyArn, requestParameters.setAsDefault, sourceIPAddress
FROM cloudtrail_logs
WHERE eventSource = 'iam.amazonaws.com'
  AND eventName = 'CreatePolicyVersion'
  AND requestParameters.setAsDefault = true
  AND requestParameters.policyDocument LIKE '%"Action":"*"%'
  AND requestParameters.policyDocument LIKE '%"Resource":"*"%'
ORDER BY eventTime DESC
