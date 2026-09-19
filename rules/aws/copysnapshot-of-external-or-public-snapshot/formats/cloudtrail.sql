SELECT eventTime, userIdentity.arn, requestParameters.sourceSnapshotId, requestParameters.sourceRegion, requestParameters.destinationRegion, recipientAccountId, sourceIPAddress
FROM cloudtrail_logs
WHERE eventSource = 'ec2.amazonaws.com'
  AND eventName = 'CopySnapshot'
  AND requestParameters.sourceSnapshotId IS NOT NULL
ORDER BY eventTime DESC
