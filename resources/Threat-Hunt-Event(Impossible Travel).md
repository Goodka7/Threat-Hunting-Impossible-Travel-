# Threat Event: Impossible Travel - Anomalous Login Locations

## Scenario Overview
A "Bad Actor" attempts to access an account from a geographically distant location in a short timeframe, simulating impossible travel.

### Steps Taken by "Bad Actor":
1. **Initial Login:**
   - Login from your VM using your current IP.
   - Access a web service or application using your credentials.
2. **Simulated Travel:**
   - Use a VPN or proxy to switch to a different geographic location (e.g., the US, Europe).
   - Perform another login attempt on the same service/application.
3. **Post-Attack Behavior:**
   - Attempt sensitive actions (e.g., modify user settings, view confidential data).
   - Logout after completing suspicious activity.
     
---

## Tables Used to Detect IoCs:

| **Parameter**       | **Description**                                                                 |
|---------------------|---------------------------------------------------------------------------------|
| **Name**| SigninLogs                                                                     |
| **Info**| https://learn.microsoft.com/en-us/azure/active-directory/reports-monitoring/reference-signins-log |
| **Purpose**| Used to detect login events, including timestamps, IP addresses, and geographic locations. |

| **Parameter**       | **Description**                                                                 |
|---------------------|---------------------------------------------------------------------------------|
| **Name**| AzureActivity                                                                  |
| **Info**| https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/azureactivity |
| **Purpose**         | Used to track administrative and user activities for context around anomalous logins. |

---

## Related Queries:
```kql
// Detect all login attempts, including location and IP address details
SigninLogs
| project Timestamp, UserPrincipalName, AppDisplayName, IPAddress, Location

// Identify login attempts originating from different geographic regions within a short time frame
SigninLogs
| extend TimeGap = datetime_diff('minute', next(Timestamp), Timestamp)
| where Location != next(Location) and TimeGap < 30
| project Timestamp, UserPrincipalName, IPAddress, Location, TimeGap
| order by Timestamp desc

// Flag suspicious IPs that do not match known or frequent login locations for a user
SigninLogs
| summarize count() by UserPrincipalName, Location, IPAddress
| where count_ < 5
| project UserPrincipalName, Location, IPAddress

// Detect administrative actions performed shortly after a suspicious login attempt
AzureActivity
| where Caller in (SigninLogs | where Location != next(Location) | project UserPrincipalName)
| where ActivityStatusValue == "Success"
| project EventTimeStamp, Caller, OperationName, ActivityStatusValue, ResourceId

// Check if user has repeated logins from the same suspicious IP across multiple services
SigninLogs
| summarize ServicesAccessed = make_list(AppDisplayName) by UserPrincipalName, IPAddress
| project UserPrincipalName, IPAddress, ServicesAccessed
```

---

## Created By:
- **Author Name**: James Harrington
- **Author Contact**: https://www.linkedin.com/in/Goodk47/
- **Date**: January 24, 2024

## Validated By:
- **Reviewer Name**: 
- **Reviewer Contact**: 
- **Validation Date**: 

---

## Additional Notes:
- **None**
