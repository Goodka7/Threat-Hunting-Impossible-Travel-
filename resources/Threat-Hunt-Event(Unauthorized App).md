# Threat Event (Unauthorized Application Execution)

**Unauthorized Execution of a Privileged Application**

## Steps the "Bad Actor" took to Create Logs and IoCs:
1. Download and execute a potentially dangerous application (e.g., Process Hacker) from the internet.
2. Launch the application with administrative privileges.
3. Perform actions like modifying or terminating critical processes.
4. Exit the application.

---
## Tables Used to Detect IoCs:
| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**            | DeviceProcessEvents                                                           |
| **Info**            | https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table |
| **Purpose**         | Used to detect the execution of unauthorized or suspicious applications on the device. |

| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**            | DeviceFileEvents                                                             |
| **Info**            | https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicefileevents-table |
| **Purpose**         | Used to detect the creation or modification of files that may indicate unauthorized application usage. |

| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**            | DeviceRegistryEvents                                                         |
| **Info**            | https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceregistryevents-table |
| **Purpose**         | Used to detect changes in system registry related to unauthorized application installation or execution. |

---

## Related Queries:
```kql
// Detect the download of a suspicious application
DeviceFileEvents
| where FileName in~ ("ProcessHacker.exe", "hacker.exe")
| project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessCommandLine

// Identify execution of the application
DeviceProcessEvents
| where FileName in~ ("ProcessHacker.exe", "hacker.exe")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine

// Look for elevated privileges during execution
DeviceLogonEvents
| where InitiatingProcessFileName in~ ("ProcessHacker.exe", "hacker.exe")
| where AccountElevationStatus == "Elevated"
| project Timestamp, DeviceName, AccountName, InitiatingProcessCommandLine

// Monitor registry changes made by the application
DeviceRegistryEvents
| where InitiatingProcessFileName in~ ("ProcessHacker.exe", "hacker.exe")
| project Timestamp, DeviceName, ActionType, RegistryKeyName, InitiatingProcessCommandLine

// Check if critical processes were modified or terminated
DeviceProcessEvents
| where InitiatingProcessFileName in~ ("ProcessHacker.exe", "hacker.exe")
| where ActionType in~ ("Terminate", "Suspend", "Modify")
| project Timestamp, DeviceName, TargetProcessName, InitiatingProcessCommandLine
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
