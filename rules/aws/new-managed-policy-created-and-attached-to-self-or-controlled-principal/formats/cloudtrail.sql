WITH policy_mods AS (
  SELECT userIdentity.arn AS actor, responseElements.policy.arn AS created_policy_arn, eventTime AS create_time
  FROM cloudtrail_logs
  WHERE eventSource = 'iam.amazonaws.com'
    AND eventName = 'CreatePolicy'
),
attach_events AS (
  SELECT userIdentity.arn AS actor, requestParameters.policyArn AS policy_arn, requestParameters.userName, requestParameters.roleName, requestParameters.groupName, eventName AS attach_event, eventTime AS attach_time
  FROM cloudtrail_logs
  WHERE eventSource = 'iam.amazonaws.com'
    AND eventName IN ('AttachUserPolicy', 'AttachRolePolicy', 'AttachGroupPolicy')
)
SELECT p.actor, p.created_policy_arn, p.create_time, s.attach_time, s.attach_event, s.userName, s.roleName, s.groupName
FROM policy_mods p
JOIN attach_events s ON p.actor = s.actor
  AND p.created_policy_arn = s.policy_arn
  AND s.attach_time > p.create_time
  AND s.attach_time <= p.create_time + INTERVAL '15' MINUTE
ORDER BY p.create_time DESC
