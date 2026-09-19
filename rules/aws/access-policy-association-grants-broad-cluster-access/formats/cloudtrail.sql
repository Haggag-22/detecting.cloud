SELECT eventTime, userIdentity.arn, requestParameters.clusterName, requestParameters.principalArn, requestParameters.policyArn, requestParameters.accessScope, sourceIPAddress
FROM cloudtrail_logs
WHERE eventSource = 'eks.amazonaws.com'
  AND eventName = 'AssociateAccessPolicy'
  AND (requestParameters.policyArn LIKE '%ClusterAdmin%'
    OR requestParameters.policyArn LIKE '%AdminView%'
    OR requestParameters.policyArn LIKE '%AmazonEKSClusterAdminPolicy%'
    OR requestParameters.policyArn LIKE '%AmazonEKSAdminViewPolicy%'
    OR requestParameters.accessScope LIKE '%cluster%')
ORDER BY eventTime DESC
