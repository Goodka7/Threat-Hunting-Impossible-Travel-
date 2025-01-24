# Threat Event (Privilege Escalation)
**Exploitation of Known Vulnerabilities for Privilege Escalation**

## Steps the "Bad Actor" Took to Create Logs and IoCs:
1. **Reconnaissance**: The attacker gathers information about the target system.
   - Uses tools like Nmap, Nessus, or Metasploit to scan for unpatched vulnerabilities.
2. **Exploit Selection**: The attacker selects an appropriate exploit based on the identified vulnerabilities (e.g., EternalBlue, CVE-2021-34527).
3. **Exploit Execution**: The attacker runs the exploit, often leveraging Metasploit or custom scripts.
   - This may result in the execution of arbitrary code with elevated privileges.
4. **Privilege Escalation**: The attacker gains higher privileges (e.g., SYSTEM or Administrator access).
5. **Persistence**: The attacker may install persistence mechanisms such as creating new user accounts or installing rootkits.

---

## Tables Used to Detect IoCs:

| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**            | DeviceProcessEvents                                                           |
| **Info**            | [Link to DeviceProcessEvents Table](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table) |
| **Purpose**         | Used to detect execution of exploit code and processes related to privilege escalation. |
| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**            | DeviceLogonEvents                                                            |
| **Info**            | [Link to DeviceLogonEvents Table](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicelogonevents-table) |
| **Purpose**         | Used to detect login activity after privilege escalation has occurred. |
| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**            | DeviceRegistryEvents                                                          |
| **Info**            | [Link to DeviceRegistryEvents Table](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceregistryevents-table) |
| **Purpose**         | Used to detect changes to registry keys that may indicate persistence mechanisms after privilege escalation. |

---

## Related Queries:
```kql
// Detecting execution of known exploits
DeviceProcessEvents
| where FileName in ('eternalblue.exe', 'ms17-010.exe', 'CVE-2021-34527.exe')
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, FileName

// Detecting creation of new user accounts after privilege escalation
DeviceRegistryEvents
| where RegistryKey == "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Userinit"
| project Timestamp, DeviceName, AccountName, ActionType, RegistryValueData

// Detecting high-privilege logins (post-exploitation)
DeviceLogonEvents
| where LogonType == 2 // Interactive login (console)
| where AccountType == "Administrator" or AccountType == "SYSTEM"
| project Timestamp, DeviceName, AccountName, SourceIP, ActionType
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
