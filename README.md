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

### 2. Searched the `DeviceLogonEvents` Table again

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
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/45288972-df92-47bb-9acc-45959bc34f3d">

---

### 3. Searched the `DeviceNetworksEvents` Table

### Process and Network Activity Analysis

Searched for process and network events on the device `windows-target-1` to correlate with login activity associated with `labuser`.

The dataset reveals network activity involving external connections that align with the simulated login traffic. On **Jan 27, 2025, at 11:12:31 AM**, an external connection was made to `135.237.186.85`, which matches the IP address associated with the earlier login event. At **11:14:46 AM**, another connection was observed to `89.117.41.164`, which corresponds to the second recorded login from a distinct geographic location. These connections were initiated shortly after the logins and suggest that the system communicated with external servers following user authentication.

No unusual processes such as `cmd.exe` or `powershell.exe` were identified in this dataset. The network activity captured confirms the geographic disparity between login events, further supporting the Impossible Travel behavior. Additional validation against other datasets may provide further insight into whether this activity reflects legitimate access or potential obfuscation techniques.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "windows-target-1"
| project Timestamp, DeviceName, RemoteIP, LocalIP, ActionType, InitiatingProcessCommandLine
| order by Timestamp desc
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/ecd7b602-46fc-479c-912b-056e058b1963">

---

### 4. Searched the `DeviceProcessEvents` Table

### Analysis of `DeviceProcessEvents`

Searched for evidence of tools or scripts used to simulate logins or tamper with authentication mechanisms on the device `windows-target-1`.

The dataset reveals multiple instances of `cmd.exe` executed by the account `labuser` on `windows-target-1`. On **Jan 27, 2025, at 11:15:06 AM**, `cmd.exe` was executed, followed by another execution at **11:12:48 AM**. An earlier execution of `cmd.exe` was recorded at **10:36:26 AM**. No other tools, such as `powershell.exe`, were identified in this dataset.

The use of `cmd.exe` aligns with expected behavior in the context of this analysis, as it was used during the simulation to generate network-related commands, such as `ipconfig`. Further validation against other datasets may help determine whether this activity was part of a controlled simulation or indicative of unauthorized actions.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "windows-target-1" and AccountName == "labuser"
| where FileName in ("powershell.exe", "cmd.exe")
| project Timestamp, AccountName, DeviceName, FileName, ProcessCommandLine
| order by Timestamp desc
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
