WITH enum_evt AS (
  SELECT userIdentity.arn AS actor, eventTime AS enum_time
  FROM cloudtrail_logs
  WHERE eventSource = 'ses.amazonaws.com'
    AND eventName IN ('ListIdentities', 'GetIdentityVerificationAttributes')
),
abuse_evt AS (
  SELECT userIdentity.arn AS actor, eventTime AS abuse_time, eventName
  FROM cloudtrail_logs
  WHERE (eventSource = 'ses.amazonaws.com' AND eventName IN ('PutIdentityPolicy', 'SetIdentityNotificationTopic', 'VerifyEmailIdentity'))
    OR eventName = 'CreateAccessKey'
)
SELECT e.actor, e.enum_time, a.abuse_time, a.eventName
FROM enum_evt e
JOIN abuse_evt a ON e.actor = a.actor
  AND a.abuse_time > e.enum_time
  AND a.abuse_time <= e.enum_time + INTERVAL '30' MINUTE
ORDER BY e.enum_time DESC
