SELECT eventTime, userIdentity.arn, eventName, requestParameters.bucketName, recipientAccountId, sourceIPAddress
FROM cloudtrail_logs
WHERE eventSource = 's3.amazonaws.com'
  AND eventName = 'CreateBucket'
ORDER BY eventTime DESC
-- Enrich: Join with baseline of (bucketName) from DeleteBucket events where bucket was CloudFront origin
