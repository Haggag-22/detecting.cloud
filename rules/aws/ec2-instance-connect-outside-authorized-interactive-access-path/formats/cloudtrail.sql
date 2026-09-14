SELECT eventTime, userIdentity.type, userIdentity.arn, userIdentity.sessionContext.sessionIssuer.arn, requestParameters.instanceId, sourceIPAddress
FROM cloudtrail_logs
WHERE eventSource = 'ec2-instance-connect.amazonaws.com'
  AND eventName = 'SendSSHPublicKey'
  AND userIdentity.arn NOT LIKE '%/role/Admin%'
  AND userIdentity.arn NOT LIKE '%/role/Platform%'
  AND userIdentity.arn NOT LIKE '%/role/Ops%'
  AND userIdentity.arn NOT LIKE '%/role/DevOps%'
  AND userIdentity.arn NOT LIKE '%/user/admin%'
  AND (userIdentity.sessionContext.sessionIssuer.arn IS NULL OR (userIdentity.sessionContext.sessionIssuer.arn NOT LIKE '%/role/Admin%' AND userIdentity.sessionContext.sessionIssuer.arn NOT LIKE '%/role/Platform%' AND userIdentity.sessionContext.sessionIssuer.arn NOT LIKE '%/role/Ops%'))
ORDER BY eventTime DESC
