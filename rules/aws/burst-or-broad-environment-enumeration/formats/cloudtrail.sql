SELECT userIdentity.arn AS actor, COUNT(DISTINCT requestParameters.applicationName || '##' || COALESCE(requestParameters.environmentName, '')) AS distinct_envs
FROM cloudtrail_logs
WHERE eventSource = 'elasticbeanstalk.amazonaws.com'
  AND eventName = 'DescribeConfigurationSettings'
GROUP BY userIdentity.arn
HAVING COUNT(DISTINCT requestParameters.applicationName || '##' || COALESCE(requestParameters.environmentName, '')) > 5
ORDER BY distinct_envs DESC
