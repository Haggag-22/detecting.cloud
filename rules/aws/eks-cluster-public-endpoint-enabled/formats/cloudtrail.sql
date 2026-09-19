SELECT eventTime, userIdentity.type, userIdentity.arn, requestParameters.name, requestParameters.resourcesVpcConfig, sourceIPAddress
FROM cloudtrail_logs
WHERE eventSource = 'eks.amazonaws.com'
  AND eventName IN ('CreateCluster', 'UpdateClusterConfig')
  AND (
    requestParameters.resourcesVpcConfig.endpointPublicAccess = true
    OR requestParameters.resourcesVpcConfig.publicAccessCidrs LIKE '%0.0.0.0/0%'
  )
ORDER BY eventTime DESC
