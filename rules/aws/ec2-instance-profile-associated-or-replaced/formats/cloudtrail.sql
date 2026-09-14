SELECT eventTime, userIdentity.arn, eventName, requestParameters.instanceId, requestParameters.iamInstanceProfile, sourceIPAddress
FROM cloudtrail_logs
WHERE eventSource = 'ec2.amazonaws.com'
  AND eventName IN ('AssociateIamInstanceProfile', 'ReplaceIamInstanceProfileAssociation')
ORDER BY eventTime DESC
