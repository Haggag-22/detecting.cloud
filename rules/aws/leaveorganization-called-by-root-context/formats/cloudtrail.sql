SELECT eventTime, userIdentity.type, userIdentity.accountId, recipientAccountId, errorCode, sourceIPAddress
FROM cloudtrail_logs
WHERE eventSource = 'organizations.amazonaws.com'
  AND eventName = 'LeaveOrganization'
  AND userIdentity.type = 'Root'
ORDER BY eventTime DESC
