WITH role_created AS (
  SELECT requestParameters.roleName AS role_name, eventTime AS create_time, recipientAccountId
  FROM cloudtrail_logs
  WHERE eventSource = 'iam.amazonaws.com'
    AND eventName = 'CreateRole'
),
role_assumed AS (
  SELECT requestParameters.roleArn, regexp_extract(requestParameters.roleArn, 'role/([^/]+)$', 1) AS role_name, eventTime AS assume_time, recipientAccountId
  FROM cloudtrail_logs
  WHERE eventSource = 'sts.amazonaws.com'
    AND eventName = 'AssumeRole'
)
SELECT r.role_name, r.create_time, a.assume_time, a.roleArn
FROM role_created r
JOIN role_assumed a ON r.role_name = a.role_name
  AND r.recipientAccountId = a.recipientAccountId
  AND a.assume_time > r.create_time
  AND a.assume_time <= r.create_time + INTERVAL '30' MINUTE
ORDER BY r.create_time DESC
