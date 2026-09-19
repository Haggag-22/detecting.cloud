WITH ec2_launch AS (
  SELECT userIdentity.arn AS actor, eventTime AS launch_time
  FROM cloudtrail_logs
  WHERE eventSource = 'ec2.amazonaws.com'
    AND ((eventName = 'RunInstances' AND requestParameters.iamInstanceProfile IS NOT NULL)
      OR eventName IN ('AssociateIamInstanceProfile', 'ReplaceIamInstanceProfileAssociation'))
),
sensitive_use AS (
  SELECT userIdentity.arn AS actor, eventTime AS use_time, eventName
  FROM cloudtrail_logs
  WHERE eventName IN ('AssumeRole', 'GetSecretValue', 'CreateSnapshot', 'AttachRolePolicy', 'PutRolePolicy')
)
SELECT e.actor, e.launch_time, s.use_time, s.eventName
FROM ec2_launch e
JOIN sensitive_use s ON e.actor = s.actor
  AND s.use_time > e.launch_time
  AND s.use_time <= e.launch_time + INTERVAL '15' MINUTE
ORDER BY e.launch_time DESC
