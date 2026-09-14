SELECT eventTime, userIdentity.type, userIdentity.arn, userIdentity.accountId, errorCode, errorMessage, sourceIPAddress
FROM cloudtrail_logs
WHERE eventSource = 'organizations.amazonaws.com'
  AND eventName = 'LeaveOrganization'
  AND errorCode IS NOT NULL
  AND errorCode != ''
ORDER BY eventTime DESC
