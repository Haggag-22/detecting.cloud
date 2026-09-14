WITH copy_evt AS (
  SELECT userIdentity.arn AS actor, eventTime AS copy_time, requestParameters.sourceSnapshotId AS source_snap, requestParameters.snapshotId AS copied_snap
  FROM cloudtrail_logs
  WHERE eventSource = 'ec2.amazonaws.com'
    AND eventName = 'CopySnapshot'
),
volume_evt AS (
  SELECT userIdentity.arn AS actor, eventTime AS vol_time, eventName, requestParameters.snapshotId AS snapshot_id, requestParameters.volumeId AS volume_id
  FROM cloudtrail_logs
  WHERE eventSource = 'ec2.amazonaws.com'
    AND eventName IN ('CreateVolume', 'AttachVolume')
)
SELECT c.actor, c.copy_time, c.source_snap, c.copied_snap, v.vol_time, v.eventName, v.snapshot_id, v.volume_id
FROM copy_evt c
JOIN volume_evt v ON c.actor = v.actor
  AND v.vol_time > c.copy_time
  AND v.vol_time <= c.copy_time + INTERVAL '2' HOUR
ORDER BY c.copy_time DESC
