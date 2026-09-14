SELECT eventTime, userIdentity.arn, requestParameters.clusterName, requestParameters.principalArn, sourceIPAddress
FROM cloudtrail_logs
WHERE eventSource = 'eks.amazonaws.com'
  AND eventName = 'CreateAccessEntry'
  AND (requestParameters.principalArn LIKE '%:user/%'
    OR requestParameters.principalArn LIKE '%breakglass%'
    OR requestParameters.principalArn LIKE '%BreakGlass%'
    OR requestParameters.principalArn LIKE '%emergency%'
    OR requestParameters.principalArn LIKE '%/role/App%'
    OR requestParameters.principalArn LIKE '%/role/Workload%'
    OR requestParameters.principalArn LIKE '%/role/Service%')
ORDER BY eventTime DESC
