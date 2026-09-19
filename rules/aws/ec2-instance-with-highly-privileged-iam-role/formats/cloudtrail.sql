SELECT eventTime, userIdentity.type, userIdentity.arn, requestParameters.instanceType,
       requestParameters.iamInstanceProfile.arn, requestParameters.subnetId, sourceIPAddress
FROM cloudtrail_logs
WHERE eventSource = 'ec2.amazonaws.com'
  AND eventName = 'RunInstances'
  AND (
    requestParameters.iamInstanceProfile.arn LIKE '%Admin%'
    OR requestParameters.iamInstanceProfile.arn LIKE '%Administrator%'
    OR requestParameters.iamInstanceProfile.arn LIKE '%PowerUser%'
    OR requestParameters.iamInstanceProfile.arn LIKE '%Security%'
    OR requestParameters.iamInstanceProfile.arn LIKE '%OrganizationAccountAccessRole%'
  )
ORDER BY eventTime DESC
