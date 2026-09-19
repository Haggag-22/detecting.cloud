-- Requires baseline table of (actor, projectName) first-seen dates
SELECT eventTime, userIdentity.arn AS actor, requestParameters.projectName AS project, sourceIPAddress
FROM cloudtrail_logs
WHERE eventSource = 'codebuild.amazonaws.com'
  AND eventName = 'StartBuild'
ORDER BY eventTime DESC
-- Enrich: flag if (actor, project) is new or rare (e.g., not in baseline from last 30 days)
