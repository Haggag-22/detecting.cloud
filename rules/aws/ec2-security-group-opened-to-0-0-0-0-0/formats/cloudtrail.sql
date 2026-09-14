SELECT eventTime, userIdentity.type, userIdentity.arn, requestParameters.groupId, requestParameters.ipPermissions, sourceIPAddress
FROM cloudtrail_logs
WHERE eventSource = 'ec2.amazonaws.com'
  AND eventName = 'AuthorizeSecurityGroupIngress'
  AND requestParameters LIKE '%0.0.0.0/0%'
ORDER BY eventTime DESC
