SELECT eventTime, userIdentity.type, userIdentity.arn, userIdentity.sessionContext.sessionIssuer.arn, eventName, requestParameters.clusterName, requestParameters.principalArn, sourceIPAddress
FROM cloudtrail_logs
WHERE eventSource = 'eks.amazonaws.com'
  AND eventName IN ('CreateAccessEntry', 'AssociateAccessPolicy')
  AND userIdentity.arn NOT LIKE '%/role/Admin%'
  AND userIdentity.arn NOT LIKE '%/role/Platform%'
  AND userIdentity.arn NOT LIKE '%/role/EKS%'
  AND userIdentity.arn NOT LIKE '%/role/ClusterAdmin%'
  AND (userIdentity.principalId IS NULL OR (userIdentity.principalId NOT LIKE '%terraform%' AND userIdentity.principalId NOT LIKE '%cloudformation%'))
ORDER BY eventTime DESC
