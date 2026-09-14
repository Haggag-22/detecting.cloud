SELECT eventTime, userIdentity.type, userIdentity.arn, requestParameters.clusterName, requestParameters.principalArn, requestParameters.policyArn, requestParameters.accessScope.type, sourceIPAddress
FROM cloudtrail_logs
WHERE eventSource = 'eks.amazonaws.com'
  AND eventName = 'AssociateAccessPolicy'
  AND (
    requestParameters.policyArn LIKE '%AmazonEKSClusterAdminPolicy%'
    OR requestParameters.policyArn LIKE '%AmazonEKSAdminPolicy%'
  )
  AND requestParameters.accessScope.type = 'cluster'
ORDER BY eventTime DESC
