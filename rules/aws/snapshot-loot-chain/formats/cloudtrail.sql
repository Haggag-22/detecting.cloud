WITH chain AS (
  SELECT userIdentity.arn AS actor, eventTime, eventName,
    requestParameters.snapshotId AS snap_id,
    requestParameters.sourceSnapshotId AS source_snap,
    requestParameters.createVolumePermission
  FROM cloudtrail_logs
  WHERE eventSource = 'ec2.amazonaws.com'
    AND eventName IN ('CreateSnapshot', 'CreateSnapshots', 'ModifySnapshotAttribute', 'CopySnapshot', 'CreateVolume', 'AttachVolume')
)
SELECT actor, eventTime, eventName, snap_id, source_snap
FROM chain
WHERE actor IN (
  SELECT actor FROM chain
  GROUP BY actor
  HAVING COUNT(DISTINCT eventName) >= 3
    AND MAX(CASE WHEN eventName IN ('CreateSnapshot','CreateSnapshots') THEN 1 ELSE 0 END) = 1
    AND MAX(CASE WHEN eventName IN ('ModifySnapshotAttribute','CopySnapshot') THEN 1 ELSE 0 END) = 1
    AND MAX(CASE WHEN eventName IN ('CreateVolume','AttachVolume') THEN 1 ELSE 0 END) = 1
)
ORDER BY eventTime DESC
