WITH leave_evt AS (
  SELECT recipientAccountId AS acct, userIdentity.arn AS actor, eventTime AS leave_time
  FROM cloudtrail_logs
  WHERE eventSource = 'organizations.amazonaws.com'
    AND eventName = 'LeaveOrganization'
),
sensitive_evt AS (
  SELECT userIdentity.accountId AS acct, userIdentity.arn AS actor, eventTime AS sus_time, eventName
  FROM cloudtrail_logs
  WHERE eventName IN ('PutUserPolicy', 'AttachRolePolicy', 'PutRolePolicy', 'CreateAccessKey', 'PutKeyPolicy', 'UpdateTrail', 'StopLogging')
)
SELECT l.acct, l.actor, l.leave_time, s.sus_time, s.eventName
FROM leave_evt l
JOIN sensitive_evt s ON l.acct = s.acct
  AND s.sus_time > l.leave_time
  AND s.sus_time <= l.leave_time + INTERVAL '1' HOUR
ORDER BY l.leave_time DESC
