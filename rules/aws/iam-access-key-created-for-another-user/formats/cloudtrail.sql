SELECT eventTime, userIdentity.type, userIdentity.userName, userIdentity.arn, requestParameters.userName, responseElements.accessKey.accessKeyId, sourceIPAddress
FROM cloudtrail_logs
WHERE eventSource = 'iam.amazonaws.com'
  AND eventName = 'CreateAccessKey'
  AND requestParameters.userName IS NOT NULL
  AND (
    (userIdentity.type = 'IAMUser' AND userIdentity.userName <> requestParameters.userName)
    OR userIdentity.type <> 'IAMUser'
  )
ORDER BY eventTime DESC
