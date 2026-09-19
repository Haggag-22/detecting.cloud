SELECT eventTime, userIdentity.type, userIdentity.arn, requestParameters.family, requestParameters.taskRoleArn, requestParameters.containerDefinitions, sourceIPAddress
FROM cloudtrail_logs
WHERE eventSource = 'ecs.amazonaws.com'
  AND eventName = 'RegisterTaskDefinition'
  AND (
    requestParameters.containerDefinitions LIKE '%docker.io/%'
    OR requestParameters.containerDefinitions LIKE '%ghcr.io/%'
    OR requestParameters.containerDefinitions LIKE '%quay.io/%'
  )
ORDER BY eventTime DESC
