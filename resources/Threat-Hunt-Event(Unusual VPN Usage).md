# Threat Event (Unusual VPN Usage)
**Unusual VPN Usage Detected from Non-Standard Locations**

## Steps the "Bad Actor" Took to Create Logs and IoCs:
1. **VPN Connection Attempt**: The attacker connects to the organization's VPN, appearing from an unusual geographic location or device.
2. **Authentication**: The attacker successfully authenticates using stolen credentials (or exploits weak authentication methods).
3. **Abnormal Access Patterns**: The attacker begins accessing sensitive internal resources that are not typically required for their role.
4. **Lateral Movement**: The attacker may attempt to move laterally within the organization, utilizing the VPN connection for internal access.
5. **Cleanup**: The attacker may attempt to delete logs or use anti-forensics tools to evade detection.

---

## Tables Used to Detect IoCs:

| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**            | DeviceNetworkEvents                                                           |
| **Info**            | [Link to DeviceNetworkEvents Table](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicenetworkevents-table) |
| **Purpose**         | Used to detect VPN connection attempts from unusual IP addresses or locations. |
| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**            | DeviceLogonEvents                                                             |
| **Info**            | [Link to DeviceLogonEvents Table](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicelogonevents-table) |
| **Purpose**         | Used to detect logins from unexpected locations or at unusual times. |
| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**            | DeviceProcessEvents                                                           |
| **Info**            | [Link to DeviceProcessEvents Table](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table) |
| **Purpose**         | Used to detect VPN client software usage (e.g., Cisco AnyConnect, OpenVPN). |

---

## Related Queries:
```kql
// Detecting VPN connection attempts from non-standard locations
DeviceNetworkEvents
| where RemoteIP !in ("known vpn IPs")  // Define known VPN IPs to compare
| where InitiatingProcessFileName == "vpnclient.exe" // Adjust for your VPN client name
| project Timestamp, DeviceName, RemoteIP, InitiatingProcessFileName

// Detecting VPN login from unusual times or geographic locations
DeviceLogonEvents
| where LogonTime between (datetime(2025-01-20) .. datetime(2025-01-21)) // Adjust date range
| where RemoteIP != "known locations"
| project Timestamp, DeviceName, AccountName, LogonTime, RemoteIP

// Detecting abnormal access patterns after VPN login
DeviceNetworkEvents
| where InitiatingProcessFileName == "vpnclient.exe"
| where RemoteIP in ("Internal IP ranges")
| project Timestamp, DeviceName, AccountName, RemoteIP, RemotePort
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
