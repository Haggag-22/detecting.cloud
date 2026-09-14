WITH delete_evt AS (
  SELECT userIdentity.arn AS actor, eventTime AS delete_time
  FROM cloudtrail_logs
  WHERE eventSource = 'ec2.amazonaws.com'
    AND eventName = 'DeleteFlowLogs'
),
suspicious_evt AS (
  SELECT userIdentity.arn AS actor, eventTime AS sus_time, eventName
  FROM cloudtrail_logs
  WHERE eventName IN ('AttachInternetGateway', 'CreateRoute', 'AuthorizeSecurityGroupIngress', 'AuthorizeSecurityGroupEgress', 'CreateNetworkAclEntry', 'ModifySnapshotAttribute', 'GetSecretValue', 'Decrypt')
)
SELECT d.actor, d.delete_time, s.sus_time, s.eventName
FROM delete_evt d
JOIN suspicious_evt s ON d.actor = s.actor
  AND s.sus_time > d.delete_time
  AND s.sus_time <= d.delete_time + INTERVAL '30' MINUTE
ORDER BY d.delete_time DESC
