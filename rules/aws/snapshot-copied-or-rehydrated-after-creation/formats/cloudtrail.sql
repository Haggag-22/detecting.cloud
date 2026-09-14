WITH create_evt AS (
  SELECT userIdentity.arn AS actor, eventTime AS create_time,
    requestParameters.snapshotId AS snap_id,
    requestParameters.volumeId AS volume_id
  FROM cloudtrail_logs
  WHERE eventSource = 'ec2.amazonaws.com'
    AND eventName IN ('CreateSnapshot', 'CreateSnapshots')
),
rehydrate_evt AS (
  SELECT userIdentity.arn AS actor, eventTime AS rehydrate_time, eventName,
    requestParameters.sourceSnapshotId AS source_snap_id,
    requestParameters.snapshotId AS snapshot_id,
    requestParameters.volumeId AS volume_id
  FROM cloudtrail_logs
  WHERE eventSource = 'ec2.amazonaws.com'
    AND eventName IN ('CopySnapshot', 'CreateVolume', 'AttachVolume')
)
SELECT c.actor, c.create_time, r.rehydrate_time, r.eventName, r.source_snap_id, r.snapshot_id, r.volume_id
FROM create_evt c
JOIN rehydrate_evt r ON c.actor = r.actor
  AND r.rehydrate_time > c.create_time
  AND r.rehydrate_time <= c.create_time + INTERVAL '2' HOUR
ORDER BY c.create_time DESC
