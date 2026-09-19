SELECT userIdentity.arn, date_trunc('minute', from_iso8601_timestamp(eventTime)) AS minute_bucket, approx_distinct(requestParameters.secretId) AS distinct_secrets, count(*) AS retrievals
FROM cloudtrail_logs
WHERE eventSource = 'secretsmanager.amazonaws.com'
  AND eventName = 'GetSecretValue'
GROUP BY 1, 2
HAVING approx_distinct(requestParameters.secretId) > 5
ORDER BY minute_bucket DESC
