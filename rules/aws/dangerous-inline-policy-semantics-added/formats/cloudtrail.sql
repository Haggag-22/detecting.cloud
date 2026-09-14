SELECT eventTime, userIdentity.arn, eventName, requestParameters.roleName, requestParameters.userName, requestParameters.policyDocument
FROM cloudtrail_logs
WHERE eventSource = 'iam.amazonaws.com'
  AND eventName IN ('PutRolePolicy', 'PutUserPolicy')
  AND (
    requestParameters.policyDocument LIKE '%"Action":"*"%'
    OR requestParameters.policyDocument LIKE '%"Resource":"*"%'
    OR requestParameters.policyDocument LIKE '%iam:*%'
    OR requestParameters.policyDocument LIKE '%sts:AssumeRole%'
    OR requestParameters.policyDocument LIKE '%iam:PassRole%'
    OR requestParameters.policyDocument LIKE '%kms:Decrypt%'
    OR requestParameters.policyDocument LIKE '%secretsmanager:GetSecretValue%'
    OR requestParameters.policyDocument LIKE '%s3:GetObject%'
  )
ORDER BY eventTime DESC
