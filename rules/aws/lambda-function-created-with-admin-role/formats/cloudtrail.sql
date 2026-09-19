SELECT eventTime, userIdentity.type, userIdentity.arn, requestParameters.functionName, requestParameters.role, sourceIPAddress
FROM cloudtrail_logs
WHERE eventSource = 'lambda.amazonaws.com'
  AND eventName = 'CreateFunction20150331'
  AND (
    requestParameters.role LIKE '%Admin%'
    OR requestParameters.role LIKE '%AdministratorAccess%'
    OR requestParameters.role LIKE '%PowerUser%'
    OR requestParameters.role LIKE '%OrganizationAccountAccessRole%'
    OR requestParameters.role LIKE '%Security%'
  )
ORDER BY eventTime DESC
