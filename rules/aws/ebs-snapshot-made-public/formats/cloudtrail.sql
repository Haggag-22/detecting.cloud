SELECT eventTime, userIdentity.type, userIdentity.arn, requestParameters.snapshotId, sourceIPAddress
FROM cloudtrail_logs
WHERE eventSource = 'ec2.amazonaws.com'
  AND eventName = 'ModifySnapshotAttribute'
  AND (
    requestParameters LIKE '%"group":"all"%'
    OR requestParameters LIKE '%"groupNames"%all%'
  )
ORDER BY eventTime DESC
