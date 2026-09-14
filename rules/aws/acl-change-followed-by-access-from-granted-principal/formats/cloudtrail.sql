WITH acl_evt AS (
  SELECT userIdentity.arn AS actor, eventTime AS acl_time, requestParameters.bucketName AS bucket
  FROM cloudtrail_logs
  WHERE eventSource = 's3.amazonaws.com'
    AND eventName IN ('PutBucketAcl', 'PutObjectAcl')
),
access_evt AS (
  SELECT userIdentity.arn AS actor, eventTime AS access_time, requestParameters.bucketName AS bucket, eventName
  FROM cloudtrail_logs
  WHERE eventSource = 's3.amazonaws.com'
    AND eventName IN ('GetObject', 'ListBucket', 'PutObject')
)
SELECT a.actor, a.bucket, a.acl_time, e.access_time, e.eventName
FROM acl_evt a
JOIN access_evt e ON a.bucket = e.bucket
  AND e.access_time > a.acl_time
  AND e.access_time <= a.acl_time + INTERVAL '1' HOUR
ORDER BY a.acl_time DESC
