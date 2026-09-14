SELECT eventTime, userIdentity.arn, eventName, requestParameters.flowLogIds, sourceIPAddress
FROM cloudtrail_logs
WHERE eventSource = 'ec2.amazonaws.com'
  AND eventName = 'DeleteFlowLogs'
ORDER BY eventTime DESC
-- Enrich: Join with DescribeFlowLogs/DescribeVpcs to identify prod/egress/security VPCs
