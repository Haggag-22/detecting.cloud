WITH beanstalk_evt AS (
  SELECT userIdentity.arn AS actor, eventTime AS recon_time
  FROM cloudtrail_logs
  WHERE eventSource = 'elasticbeanstalk.amazonaws.com'
    AND eventName = 'DescribeConfigurationSettings'
),
createkey_evt AS (
  SELECT userIdentity.arn AS actor, eventTime AS key_time, requestParameters.userName
  FROM cloudtrail_logs
  WHERE eventSource = 'iam.amazonaws.com'
    AND eventName = 'CreateAccessKey'
)
SELECT b.actor, b.recon_time, c.key_time, c.userName
FROM beanstalk_evt b
JOIN createkey_evt c ON b.actor = c.actor
  AND c.key_time > b.recon_time
  AND c.key_time <= b.recon_time + INTERVAL '30' MINUTE
ORDER BY b.recon_time DESC
