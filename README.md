<img width="400" src="https://github.com/user-attachments/assets/c878e233-d060-4f34-96e9-deb4bcc32fe8"/>

# Threat Hunt Report: Impossible Travel
- [Scenario Creation](https://github.com/Goodka7/Threat-Hunting-Impossible-Travel-/blob/main/resources/Threat-Hunt-Event(Impossible%20Travel).md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- PowerShell

## Scenario

Management is concerned about potential unauthorized access attempts from geographically distant locations, which may indicate compromised credentials or unauthorized user activity. Recent security logs have revealed irregular login attempts from multiple locations within a short time frame, suggesting the possibility of impossible travel. The goal is to detect suspicious login activity, such as logins from distant IPs that occur simultaneously or within an unrealistic timeframe, and analyze any related security incidents. If such activity is identified, notify management for further investigation.

### High-Level PowerShell Discovery Plan

- **Check `DeviceLogonEvents`** for suspicious logon activities, such as multiple logins from distant IP addresses in a short time frame.  
- **Check `DeviceNetworkEvents`** to identify unusual network activity, including logins from unexpected or foreign IP addresses and VPN-related connections.  
- **Check `DeviceProcessEvents`** for evidence of tools or scripts used to simulate logins or tamper with authentication mechanisms (e.g., `powershell.exe`, `cmd.exe`).  

---

## Steps Taken

### 1. Searched the `DeviceLogonEvents' Table

Searched for any suspicious logon activities, such as multiple logins from distant IP addresses in a short time.

The dataset included login events across multiple devices and user accounts, with notable activity for the account `labuser`. Logins were recorded for various devices, but the focus has been placed on the machine `windows-target-1`, which exhibited activity indicative of potential compromise. Many entries lacked `RemoteIP` details, reducing their relevance to identifying geographic or source anomalies.

**Query used to locate events:**

```kql
DeviceLogonEvents
| project Timestamp, AccountName, DeviceName, RemoteIP
| order by Timestamp desc
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/6e3da45a-4ab1-4d06-8ad3-fad9a877ae70">

---

### 2. Searched the `DeviceLogonEvents` Table

Searched for login events on the device `windows-target-1` associated with the account `labuser`.

The scope was been refined to prioritize:
- Login events originating from `windows-target-1` to identify patterns of unauthorized access.
- Activity associated with the account `labuser` to trace potential misuse of credentials.
- Available `RemoteIP` data to detect geographic variations and potential indicators of lateral movement or external compromise.

The dataset reveals multiple login events for the user `labuser` on the device `windows-target-1`, originating from two distinct IP addresses. On **Jan 27, 2025, at 11:14:46 AM**, login activity was recorded from the IP `89.117.41.164`. Earlier, at **11:12:31 AM**, a login was recorded from the IP `135.237.186.85`. These logins occurred within a short timeframe, indicating geographically disparate access points.

This activity indicates Impossible Travel, where a single account is used to log in from different locations in rapid succession. The presence of these distinct IPs suggests potential credential compromise or the use of obfuscation techniques, such as a VPN, to simulate external access. Further analysis of network and process events may provide additional context to validate this behavior.

**Query used to locate event:**

```kql
DeviceLogonEvents
| where DeviceName == "windows-target-1" and AccountName == "labuser"
| project Timestamp, AccountName, DeviceName, RemoteIP
| order by Timestamp desc
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/c4aabb61-e510-4482-bd3f-0481b04546ad">

---

### 3. Searched the `DeviceNetworksEvents` Table

Searched for any network activity that may give clues to malicious acts.

The dataset reveals significant network activity originating from the device "thscenariovm." On **Jan 26, 2025, at 12:49:12 PM**, `powershell.exe` initiated multiple successful connections to `raw.githubusercontent.com` (IP address `185.199.111.133`) over HTTPS (port 443). Similarly, another connection to `raw.githubusercontent.com` (IP address `185.199.110.133`) was observed at **1:16:15 PM**, also using `powershell.exe`. These domains are known to host scripts and files, suggesting potential script download or execution activity. 

The use of `powershell.exe` for network communication and repeated connections to script-hosting domains aligns with concerns about unauthorized activities and tampering with system configurations. These events warrant further investigation to assess whether they involve the execution of malicious scripts or unauthorized system changes.


**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "thscenariovm"
| where RemotePort in (3389, 445, 135) or RemoteUrl has_any (".onion", "raw.githubusercontent.com", "unknown-domain")
| where ActionType in ("ConnectionSuccess", "ConnectionFailed")
| project Timestamp, DeviceName, RemoteIP, RemotePort, RemoteUrl, ActionType, InitiatingProcessFileName, InitiatingProcessAccountName
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/58865235-2a2c-4c44-ab32-dd0c0b933b23">

---

### 4. Searched the `DeviceProcessEvents` Table

Further searched for unusual changes, particularly with the word "administrators" in the command line.

The dataset reveals activity related to the addition of a user to the `Administrators` group on the device "thscenariovm." On **Jan 26, 2025, at 1:08:42 PM**, the command `"net.exe" localgroup administrators NewAdminAccount /add` was executed by the user `labuser`, successfully adding the account `NewAdminAccount` to the `Administrators` group. 

Additionally, a second command, `"net.exe" localgroup administrators`, was executed at **Jan 26, 2025, at 1:09:56 PM**, listing the members of the `Administrators` group, which confirms the account was successfully added.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "thscenariovm"
| where ProcessCommandLine has "administrators"
| project Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessAccountName
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/aed5e71a-8641-4b5b-bf64-119cc0f9a010">

---

## Chronological Event Timeline

### 1. Registry Modification - Disable UAC
- **Time:** `1:03:30 PM, January 26, 2025`
- **Event:** The user "labuser" executed a command using `cmd.exe` that disabled User Account Control (UAC) by modifying the registry key `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`.
- **Action:** Registry value modification detected.
- **Command:** `Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 0`
- **Initiating Process:** `cmd.exe`

### 2. Windows Defender Disabled
- **Time:** `1:03:10 PM, January 26, 2025`
- **Event:** Windows Defender real-time monitoring was disabled via `powershell.exe` using the `Set-MpPreference` command.
- **Action:** Process executed to modify security settings.
- **Command:** `Set-MpPreference -DisableRealtimeMonitoring $true`

### 3. Administrators Group Modified
- **Time:** `1:08:42 PM, January 26, 2025`
- **Event:** The user "labuser" executed a command using `net.exe` to add the account `NewAdminAccount` to the `Administrators` group.
- **Action:** Process detected adding a new administrator account.
- **Command:** `net.exe localgroup administrators NewAdminAccount /add`
- **Initiating Process:** `net.exe`
- **Group:** `Administrators`
- **Account Name:** `NewAdminAccount`

### 4. Registry Modification - Cached Updates Deleted
- **Time:** `1:03:30 PM, January 26, 2025`
- **Event:** A registry key modification was made to delete cached standalone update binaries from `HKEY_CURRENT_USER\SOFTWARE\Microsoft\WindowsUpdate`.
- **Action:** Registry value deleted.
- **Command:** `cmd.exe /q /c del /q "C:\Users\labuser\Updates\Standalone"`
- **Initiating Process:** `cmd.exe`
- **Registry Key:** `HKEY_CURRENT_USER\SOFTWARE\Microsoft\WindowsUpdate`
- **Registry Value Name:** `Delete Cached Standalone Update Binary`

---

## Summary

The user "labuser" on the device "thscenariovm" performed a series of actions that align with tampering with critical system configurations. Key findings include the disabling of UAC and Windows Defender, as well as the addition of a new local administrator account to the `Administrators` group. These actions were executed using `cmd.exe` and `powershell.exe`, indicating deliberate attempts to weaken the system's security posture. Additionally, cached update binaries were deleted, which could disrupt system updates and prevent the application of security patches. The registry changes and process executions observed suggest potential malicious intent and warrant immediate investigation to assess the impact and prevent further exploitation.

---

## Response Taken

Unauthorized System Configuration activity was confirmed on the endpoint `thscenariovm` by the user `labuser`. The device was immediately isolated to prevent further potential misuse, and the user's direct manager was notified for follow-up investigation, remediation and potential disciplinary action.

---
