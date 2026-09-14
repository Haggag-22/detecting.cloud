SELECT eventTime, userIdentity.type, userIdentity.arn, eventName, requestParameters.name, requestParameters.isMultiRegionTrail, requestParameters.includeGlobalServiceEvents, requestParameters.enableLogFileValidation, requestParameters.isOrganizationTrail, sourceIPAddress
FROM cloudtrail_logs
WHERE eventSource = 'cloudtrail.amazonaws.com'
  AND errorCode IS NULL
  AND (
    eventName IN ('StopLogging', 'DeleteTrail')
    OR (
      eventName = 'UpdateTrail'
      AND (
        requestParameters.isMultiRegionTrail = false
        OR requestParameters.includeGlobalServiceEvents = false
        OR requestParameters.enableLogFileValidation = false
        OR requestParameters.isOrganizationTrail = false
      )
    )
  )
ORDER BY eventTime DESC
