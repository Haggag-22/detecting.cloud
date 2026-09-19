SELECT eventTime, userIdentity.type, userIdentity.arn, requestParameters.keyId, requestParameters.pendingWindowInDays, responseElements.keyState, responseElements.deletionDate, sourceIPAddress
FROM cloudtrail_logs
WHERE eventSource = 'kms.amazonaws.com'
  AND eventName = 'ScheduleKeyDeletion'
ORDER BY eventTime DESC
