SELECT interfaceId, srcAddr, dstAddr, dstPort, protocol, bytes
FROM vpc_flow_logs
WHERE interfaceId IN (SELECT interface_id FROM lambda_eni_mapping)
  AND flowDirection = 'egress'
  AND action = 'ACCEPT'
  AND dstAddr NOT LIKE '10.%'
  AND dstAddr NOT LIKE '172.16.%'
  AND dstAddr NOT LIKE '192.168.%'
  AND (dstPort IN (4444, 8080, 8443) OR bytes > 10485760)
ORDER BY start_time DESC
