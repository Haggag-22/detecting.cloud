WITH create_evt AS (
  SELECT userIdentity.arn AS actor, eventTime AS create_time, requestParameters.principalArn AS principal, requestParameters.clusterName AS cluster
  FROM cloudtrail_logs
  WHERE eventSource = 'eks.amazonaws.com'
    AND eventName = 'CreateAccessEntry'
),
assoc_evt AS (
  SELECT userIdentity.arn AS actor, eventTime AS assoc_time, requestParameters.principalArn AS principal, requestParameters.clusterName AS cluster, requestParameters.policyArn
  FROM cloudtrail_logs
  WHERE eventSource = 'eks.amazonaws.com'
    AND eventName = 'AssociateAccessPolicy'
)
SELECT c.actor, c.principal, c.cluster, c.create_time, a.assoc_time, a.policyArn
FROM create_evt c
JOIN assoc_evt a ON c.principal = a.principal AND c.cluster = a.cluster
  AND a.assoc_time > c.create_time
  AND a.assoc_time <= c.create_time + INTERVAL '15' MINUTE
ORDER BY c.create_time DESC
