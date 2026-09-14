WITH profile_created AS (
  SELECT requestParameters.userName AS target_user, eventTime AS create_time
  FROM cloudtrail_logs
  WHERE eventSource = 'iam.amazonaws.com'
    AND eventName = 'CreateLoginProfile'
),
console_login AS (
  SELECT regexp_extract(userIdentity.arn, 'user/([^/]+)$', 1) AS target_user, eventTime AS login_time
  FROM cloudtrail_logs
  WHERE eventSource = 'signin.amazonaws.com'
    AND eventName = 'ConsoleLogin'
    AND responseElements.ConsoleLogin = 'Success'
)
SELECT p.target_user, p.create_time, c.login_time
FROM profile_created p
JOIN console_login c ON p.target_user = c.target_user
  AND c.login_time > p.create_time
  AND c.login_time <= p.create_time + INTERVAL '24' HOUR
ORDER BY p.create_time DESC
