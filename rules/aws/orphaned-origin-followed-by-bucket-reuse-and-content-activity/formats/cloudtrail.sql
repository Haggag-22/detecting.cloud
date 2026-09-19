WITH create_evt AS (
  SELECT userIdentity.arn AS actor, eventTime AS create_time, requestParameters.bucketName AS bucket
  FROM cloudtrail_logs
  WHERE eventSource = 's3.amazonaws.com'
    AND eventName = 'CreateBucket'
),
put_evt AS (
  SELECT userIdentity.arn AS actor, eventTime AS put_time, requestParameters.bucketName AS bucket, eventName
  FROM cloudtrail_logs
  WHERE eventSource = 's3.amazonaws.com'
    AND eventName = 'PutObject'
)
SELECT c.actor, c.bucket, c.create_time, p.put_time
FROM create_evt c
JOIN put_evt p ON c.bucket = p.bucket
  AND p.put_time > c.create_time
  AND p.put_time <= c.create_time + INTERVAL '1' HOUR
ORDER BY c.create_time DESC
