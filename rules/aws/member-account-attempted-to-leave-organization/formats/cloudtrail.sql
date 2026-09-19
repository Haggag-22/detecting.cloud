SELECT eventTime, userIdentity.type, userIdentity.arn, userIdentity.accountId, recipientAccountId, errorCode, errorMessage, sourceIPAddress
FROM cloudtrail_logs
WHERE eventSource = 'organizations.amazonaws.com'
  AND eventName = 'LeaveOrganization'
ORDER BY eventTime DESC
