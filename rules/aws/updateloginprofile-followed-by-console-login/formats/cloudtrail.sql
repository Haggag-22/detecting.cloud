WITH profile_updated AS (
  SELECT requestParameters.userName AS target_user, eventTime AS update_time
  FROM cloudtrail_logs
  WHERE eventSource = 'iam.amazonaws.com'
    AND eventName = 'UpdateLoginProfile'
),
console_login AS (
  SELECT regexp_extract(userIdentity.arn, 'user/([^/]+)$', 1) AS target_user, eventTime AS login_time
  FROM cloudtrail_logs
  WHERE eventSource = 'signin.amazonaws.com'
    AND eventName = 'ConsoleLogin'
    AND responseElements.ConsoleLogin = 'Success'
)
SELECT p.target_user, p.update_time, c.login_time
FROM profile_updated p
JOIN console_login c ON p.target_user = c.target_user
  AND c.login_time > p.update_time
  AND c.login_time <= p.update_time + INTERVAL '1' HOUR
ORDER BY p.update_time DESC
