WITH serial_evt AS (
  SELECT userIdentity.arn AS actor, eventTime AS serial_time
  FROM cloudtrail_logs
  WHERE eventSource = 'ec2-instance-connect.amazonaws.com'
    AND eventName = 'SendSerialConsoleSSHPublicKey'
),
sensitive_evt AS (
  SELECT userIdentity.arn AS actor, eventTime AS use_time, eventName
  FROM cloudtrail_logs
  WHERE eventName IN ('UpdateLoginProfile', 'CreateLoginProfile', 'StartSession', 'PutUserPolicy', 'AttachRolePolicy', 'PutRolePolicy', 'GetSecretValue', 'CreateAccessKey')
)
SELECT e.actor, e.serial_time, s.use_time, s.eventName
FROM serial_evt e
JOIN sensitive_evt s ON e.actor = s.actor
  AND s.use_time > e.serial_time
  AND s.use_time <= e.serial_time + INTERVAL '15' MINUTE
ORDER BY e.serial_time DESC
