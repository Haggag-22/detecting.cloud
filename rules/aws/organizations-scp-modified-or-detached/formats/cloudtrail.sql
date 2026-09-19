SELECT eventTime, userIdentity.type, userIdentity.arn, eventName, requestParameters.policyId, requestParameters.targetId, requestParameters.content, sourceIPAddress
FROM cloudtrail_logs
WHERE eventSource = 'organizations.amazonaws.com'
  AND eventName IN ('DetachPolicy', 'DeletePolicy', 'UpdatePolicy')
ORDER BY eventTime DESC
