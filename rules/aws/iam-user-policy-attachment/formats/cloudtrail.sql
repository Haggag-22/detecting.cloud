SELECT eventTime, userIdentity.type, userIdentity.arn, eventName, requestParameters.userName, requestParameters.policyArn, sourceIPAddress
FROM cloudtrail_logs
WHERE eventSource = 'iam.amazonaws.com'
  AND eventName IN ('AttachUserPolicy', 'PutUserPolicy')
  AND userIdentity.principalId NOT LIKE '%terraform%'
  AND userIdentity.principalId NOT LIKE '%cloudformation%'
  AND (
    requestParameters.policyArn LIKE '%AdministratorAccess%'
    OR requestParameters.policyArn LIKE '%IAMFullAccess%'
    OR requestParameters.policyArn LIKE '%PowerUserAccess%'
    OR requestParameters.policyDocument LIKE '%"Action":"*"%'
    OR requestParameters.policyDocument LIKE '%"iam:PassRole"%'
    OR requestParameters.policyDocument LIKE '%"sts:AssumeRole"%'
    OR requestParameters.policyDocument LIKE '%"secretsmanager:GetSecretValue"%'
    OR requestParameters.policyDocument LIKE '%"kms:Decrypt"%'
  )
ORDER BY eventTime DESC
