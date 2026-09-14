WITH role_created AS (
  SELECT requestParameters.roleName AS role_name, eventTime AS create_time, recipientAccountId
  FROM cloudtrail_logs
  WHERE eventSource = 'iam.amazonaws.com'
    AND eventName = 'CreateRole'
),
policy_attached AS (
  SELECT requestParameters.roleName AS role_name, eventTime AS attach_time, eventName, requestParameters.policyArn, requestParameters.policyDocument, recipientAccountId
  FROM cloudtrail_logs
  WHERE eventSource = 'iam.amazonaws.com'
    AND eventName IN ('AttachRolePolicy', 'PutRolePolicy')
    AND (requestParameters.policyArn LIKE '%AdministratorAccess%' OR requestParameters.policyArn LIKE '%PowerUserAccess%' OR requestParameters.policyDocument LIKE '%iam:PassRole%' OR requestParameters.policyDocument LIKE '%sts:AssumeRole%' OR requestParameters.policyDocument LIKE '%secretsmanager:GetSecretValue%' OR requestParameters.policyDocument LIKE '%kms:Decrypt%' OR requestParameters.policyDocument LIKE '%"Action":"*"%')
)
SELECT r.role_name, r.create_time, p.attach_time, p.eventName, p.policyArn
FROM role_created r
JOIN policy_attached p ON r.role_name = p.role_name
  AND r.recipientAccountId = p.recipientAccountId
  AND p.attach_time > r.create_time
  AND p.attach_time <= r.create_time + INTERVAL '15' MINUTE
ORDER BY r.create_time DESC
