SELECT eventTime, userIdentity.arn, eventName, requestParameters.policyArn, requestParameters.versionId
FROM cloudtrail_logs
WHERE eventSource = 'iam.amazonaws.com'
  AND eventName = 'SetDefaultPolicyVersion'
ORDER BY eventTime DESC
