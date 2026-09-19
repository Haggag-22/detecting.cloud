SELECT userIdentity.arn, requestParameters.bucketName,
       COUNT(*) as download_count,
       COUNT(DISTINCT requestParameters.key) as distinct_objects
FROM cloudtrail_logs
WHERE eventSource = 's3.amazonaws.com'
  AND eventName = 'GetObject'
GROUP BY userIdentity.arn, requestParameters.bucketName
HAVING download_count >= 25
   AND distinct_objects >= 25
ORDER BY download_count DESC
