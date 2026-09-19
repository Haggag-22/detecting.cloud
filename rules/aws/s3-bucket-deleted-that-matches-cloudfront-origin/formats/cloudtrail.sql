SELECT eventTime, userIdentity.arn, eventName, requestParameters.bucketName, sourceIPAddress
FROM cloudtrail_logs
WHERE eventSource = 's3.amazonaws.com'
  AND eventName = 'DeleteBucket'
ORDER BY eventTime DESC
-- Enrich: Join with cloudfront:ListDistributions / DescribeDistribution to find origins matching bucket.s3.amazonaws.com
