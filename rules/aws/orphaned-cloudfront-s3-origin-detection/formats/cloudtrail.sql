-- Posture hunt: Use CloudFront ListDistributions + DescribeDistribution API
-- For each distribution, get origins with DomainName like %.s3.% or %.s3.amazonaws.com
-- For each such origin, extract bucket name and verify via S3 HeadBucket or ListBuckets
-- Flag distributions where S3 origin bucket does not exist
SELECT eventTime, eventSource, eventName, requestParameters.id
FROM cloudtrail_logs
WHERE eventSource = 'cloudfront.amazonaws.com'
  AND eventName IN ('GetDistribution', 'ListDistributions')
ORDER BY eventTime DESC
