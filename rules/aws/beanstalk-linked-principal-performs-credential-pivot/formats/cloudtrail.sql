SELECT eventTime, userIdentity.arn, userIdentity.sessionContext.sessionIssuer.arn, eventName, requestParameters.userName, requestParameters.roleArn, sourceIPAddress
FROM cloudtrail_logs
WHERE ((eventSource = 'iam.amazonaws.com' AND eventName = 'CreateAccessKey') OR (eventSource = 'sts.amazonaws.com' AND eventName = 'AssumeRole'))
ORDER BY eventTime DESC
