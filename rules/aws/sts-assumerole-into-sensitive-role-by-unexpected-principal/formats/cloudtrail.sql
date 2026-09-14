SELECT eventTime, userIdentity.type, userIdentity.arn, requestParameters.roleArn, requestParameters.roleSessionName, sourceIPAddress
FROM cloudtrail_logs
WHERE eventSource = 'sts.amazonaws.com'
  AND eventName = 'AssumeRole'
  AND (
    requestParameters.roleArn LIKE '%Admin%'
    OR requestParameters.roleArn LIKE '%Administrator%'
    OR requestParameters.roleArn LIKE '%PowerUser%'
    OR requestParameters.roleArn LIKE '%OrganizationAccountAccessRole%'
    OR requestParameters.roleArn LIKE '%Security%'
  )
  AND userIdentity.arn NOT LIKE '%/role/Admin%'
  AND userIdentity.arn NOT LIKE '%/role/Security%'
  AND userIdentity.arn NOT LIKE '%/role/Platform%'
  AND userIdentity.arn NOT LIKE '%/role/Infra%'
  AND userIdentity.arn NOT LIKE '%AWSReservedSSO_AdministratorAccess%'
ORDER BY eventTime DESC
