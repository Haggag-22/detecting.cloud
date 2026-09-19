SELECT eventTime, userIdentity.arn, userIdentity.sessionContext.sessionIssuer.arn, eventName, requestParameters.flowLogIds, sourceIPAddress
FROM cloudtrail_logs
WHERE eventSource = 'ec2.amazonaws.com'
  AND eventName = 'DeleteFlowLogs'
ORDER BY eventTime DESC
