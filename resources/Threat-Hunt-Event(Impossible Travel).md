# Threat Event (Impossible Travel)
**Anomalous Login Locations**

## Steps Taken by "Bad Actor":
1. **Initial Login:**
   - Login to "Victim" computer from a VM using "compromised" credentials.
   - Run CMD and run "ipconfig" to generate logs.
2. **Simulated Travel:**
   - Use a VPN or proxy to switch to a different geographic location (e.g., Argentina).
   - Perform another login on the same "victim" computer.
   - Run CMD and run "ipconfig" to generate logs.
3. **Post-Attack Behavior:**
   - Logout after completing "suspicious" activity.
     
---

## Tables Used to Detect IoCs:

| **Parameter**       | **Description**                                                                 |
|---------------------|---------------------------------------------------------------------------------|
| **Name**| DeviceLogonEvents                                                             |
| **Info**| https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/device-logon-events |
| **Purpose**| Used to detect login events, including timestamps, usernames, and source IP addresses. |

| **Parameter**       | **Description**                                                                 |
|---------------------|---------------------------------------------------------------------------------|
| **Name**| DeviceProcessEvents                                                          |
| **Info**| https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/device-process-events |
| **Purpose**| Used to track commands and processes executed on the victim machine, such as `ipconfig` to simulate user activity. |

| **Parameter**       | **Description**                                                                 |
|---------------------|---------------------------------------------------------------------------------|
| **Name**| DeviceNetworkEvents                                                          |
| **Info**| https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/device-network-events |
| **Purpose**| Used to detect network activity, including geographic location changes (e.g., VPN usage) and source/destination IP addresses. |

---

## Related Queries:
```kql
// Detect all login attempts, including location and IP address details
DeviceLogonEvents
| project Timestamp, AccountName, DeviceName, RemoteIpAddress

// Identify login attempts originating from different geographic regions or IPs within a short time frame
DeviceLogonEvents
| extend TimeGap = datetime_diff('minute', next(Timestamp), Timestamp)
| where RemoteIpAddress != next(RemoteIpAddress) and TimeGap < 30
| project Timestamp, AccountName, DeviceName, RemoteIpAddress, TimeGap
| order by Timestamp desc

// Flag suspicious IPs or devices that have infrequent login activity for a specific user
DeviceLogonEvents
| summarize count() by AccountName, DeviceName, RemoteIpAddress
| where count_ < 5
| project AccountName, DeviceName, RemoteIpAddress

// Detect processes executed shortly after a suspicious login attempt
DeviceProcessEvents
| where AccountName in (DeviceLogonEvents | where RemoteIpAddress != next(RemoteIpAddress) | project AccountName)
| project Timestamp, AccountName, DeviceName, ProcessCommandLine

// Check if a user performs logins from multiple devices or IPs across different locations in quick succession
DeviceLogonEvents
| summarize DevicesAccessed = make_list(DeviceName) by AccountName, RemoteIpAddress
| project AccountName, RemoteIpAddress, DevicesAccessed
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
