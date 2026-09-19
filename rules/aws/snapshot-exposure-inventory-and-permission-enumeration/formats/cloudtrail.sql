-- Hunt: List snapshots then check createVolumePermission
-- Step 1: Get snapshot IDs from DescribeSnapshots (owner-ids self)
-- Step 2: For each snapshot, DescribeSnapshotAttribute(attribute=createVolumePermission)
-- Filter results where createVolumePermission contains group=all or non-self userIds
SELECT eventTime, userIdentity.arn, requestParameters.snapshotId, responseElements
FROM cloudtrail_logs
WHERE eventSource = 'ec2.amazonaws.com'
  AND eventName = 'DescribeSnapshotAttribute'
  AND requestParameters.attribute = 'createVolumePermission'
ORDER BY eventTime DESC
