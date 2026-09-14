SELECT eventTime, userIdentity.arn, requestParameters.snapshotId, requestParameters.createVolumePermission, sourceIPAddress
FROM cloudtrail_logs
WHERE eventSource = 'ec2.amazonaws.com'
  AND eventName = 'ModifySnapshotAttribute'
  AND requestParameters.createVolumePermission.add.userIds IS NOT NULL
ORDER BY eventTime DESC
