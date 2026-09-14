SELECT actor, time_bucket, cnt
FROM (
  SELECT userIdentity.arn AS actor,
    date_trunc('minute', eventTime) AS time_bucket,
    COUNT(*) AS cnt
  FROM cloudtrail_logs
  WHERE eventSource = 'ses.amazonaws.com'
    AND eventName IN ('ListIdentities', 'GetIdentityVerificationAttributes')
  GROUP BY 1, 2
  HAVING COUNT(*) > 5
) t
ORDER BY cnt DESC
