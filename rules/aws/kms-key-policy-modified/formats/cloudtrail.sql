SELECT eventTime, userIdentity.type, userIdentity.arn, requestParameters.keyId, requestParameters.policyName, sourceIPAddress
FROM cloudtrail_logs
WHERE eventSource = 'kms.amazonaws.com'
  AND eventName = 'PutKeyPolicy'
  AND (
    requestParameters.policy LIKE '%"Principal":"*"%'
    OR requestParameters.policy LIKE '%"Principal":{"AWS":"*"}%'
    OR requestParameters.policy LIKE '%:root"%'
    OR requestParameters.policy LIKE '%"kms:*"%'
    OR requestParameters.policy LIKE '%"kms:Decrypt"%'
    OR requestParameters.policy LIKE '%"kms:GenerateDataKey%'
    OR requestParameters.policy LIKE '%"kms:CreateGrant"%'
    OR requestParameters.policy LIKE '%"kms:PutKeyPolicy"%'
    OR requestParameters.policy LIKE '%"kms:ScheduleKeyDeletion"%'
    OR requestParameters.bypassPolicyLockoutSafetyCheck = true
  )
ORDER BY eventTime DESC
