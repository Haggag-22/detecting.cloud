SELECT eventTime, userIdentity.arn, requestParameters.snapshotId, requestParameters.groupNames, requestParameters.createVolumePermission, sourceIPAddress
FROM cloudtrail_logs
WHERE eventSource = 'ec2.amazonaws.com'
  AND eventName = 'ModifySnapshotAttribute'
  AND (requestParameters.groupNames LIKE '%all%'
    OR JSON_EXTRACT_SCALAR(requestParameters.createVolumePermission, '$.add.groups') LIKE '%all%')
ORDER BY eventTime DESC
