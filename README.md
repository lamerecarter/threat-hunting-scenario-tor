<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/lamerecarter/threat-hunting-scenario-tor/blob/main/Create%20threat-hunting-scenario-tor-event-creation.md) 

## Platforms and Languages Leveraged
- Windows 11 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched for any file that had the string "tor" in it and discovered what looks like the user "employee" downloaded a TOR installer, did something that resulted in many TOR-related files being copied to the desktop, and the creation of a file called `tor-shopping-list.txt` on the desktop at `2025-11-15T21:21:28.6013653Z`. These events began at `2025-11-15T21:05:52.0880206Z`.

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "threat-hunt-lab"
| where FileName contains "tor"
| where Timestamp >= datetime(2025-11-15T21:05:52.0880206Z)
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName

```
<img width="1240" height="977" alt="image" src="https://github.com/user-attachments/assets/342bdeaf-cecb-43b2-a963-28a18a42221b" />


---

### 2. Searched the `DeviceProcessEvents` Table

Searched for any `DeviceProcessEvents` that contained the string "tor-browser-windows-x86_64-portable-14.0.1.exe". Based on the logs returned, at `2025-11-15T21:05:52.6579849Z`, an employee on the "threat-hunt-lab" device ran the file `tor-browser-windows-x86_64-portable-14.0.1.exe` from their Downloads folder, using a command that triggered a silent installation.

**Query used to locate event:**

```kql

DeviceProcessEvents
| where DeviceName == "threat-hunt-lab"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable"
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```
<img width="1653" height="525" alt="image" src="https://github.com/user-attachments/assets/e2636d84-0c12-4dcb-b9e6-61c00a118007" />


---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched for any indication that user "employee" actually opened the TOR browser. There was evidence that they did open it at `2025-11-15T21:12:17.6290405Z`. There were several other instances of `firefox.exe` (TOR) as well as `tor.exe` spawned afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents  
| where DeviceName == "threat-hunt-lab"  
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")  
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine  
| order by Timestamp desc
```
<img width="1649" height="776" alt="image" src="https://github.com/user-attachments/assets/dc588787-1598-4e1e-8d90-9e5c78383f56" />


---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched for any indication the TOR browser was used to establish a connection using any of the known TOR ports. At `2025-11-15T21:12:40.156097Z`, an employee on the "threat-hunt-lab" device successfully established a connection to the remote IP address `127.0.0.1 on port `9151`. The connection was initiated by the process `tor.exe`, located in the folder `c:\users\lamere\desktop\tor browser\browser\firefox.exe`. There were a couple of other connections to sites over ports `9151` & '9150'.

**Query used to locate events:**

```kql
DeviceNetworkEvents  
| where DeviceName == "threat-hunt-lab"  
| where InitiatingProcessAccountName != "system"  
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe")  
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150", "80", "443")  
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath  
| order by Timestamp desc
```
<img width="1675" height="491" alt="image" src="https://github.com/user-attachments/assets/873721c8-11b0-47ce-bfd1-a3b9ef26a228" />


---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- 2025-11-15T21:05:52Z — Start of Investigator’s Query Window
- I began searching all activity on the device “threat-hunt-lab” for anything containing the string “tor”.
- This timestamp is your reference point for reviewing all Tor-related events.

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `2025-11-15T21:11:23Z`
- **Event:** The Tor portable installer ran without any prompts or UI, indicating intentional or automated silent execution.
- **Action:** Tor Browser Installer Executed Silently.
- **Command:** `tor-browser-windows-x86_64-portable-14.0.1.exe /S`
- **File Path:** `c:\users\lamere\desktop\tor browser\browser\firefox.exe`

### 3. Tor Browser (Firefox.exe) Launched

- **Timestamp:** `2024-11-08T22:17:21.6357935Z`
- **Event:** User "employee" opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `c:\users\lamere\desktop\tor browser\browser\firefox.exe`

### 4. Network Connection - TOR Network

- **Timestamp:** `2025-11-15T21:12:17Z`
- **Event:** Following the initial launch, multiple processes appeared, including:
  
- firefox.exe (Tor Browser UI processes)
- tor.exe (Tor routing engine)
- Additional content processes spawned by Firefox (tabs, sandboxed processes)

- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `c:\users\lamere\desktop\tor browser\browser\firefox.exe`

### 5. Additional Network Connections - TOR Browser Activity

- **Timestamps:**
  - `2025-11-15T21:12:40Z` - Connected to `127.0.0.1:9151` on port `9151`.
- **Event:** Additional TOR network connections were established, indicating ongoing activity by user "lamere" through the TOR browser.
- **Action:** Multiple successful connections detected.  A connection to localhost:9151 proves the Tor Browser internally activated its Tor daemon.

### 6. File Creation - TOR Shopping List

- **Timestamp:** Between 21:12:17Z and 21:21:28Z — Tor Browser Creates Files on Desktop
- **Event:** The user "lamere" created a file named `tor-shopping-list.txt` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\lamere\Desktop\tor-shopping-list.txt`

---

## Summary

Between 21:11 and 21:22 UTC on November 15, 2025, a sequence of events clearly demonstrates that user “lamere” intentionally downloaded, silently installed, launched and actively used the Tor Browser on the device “threat-hunt-lab.”

Key highlights:
- The Tor Browser installer ran in silent mode, indicating deliberate execution with no user prompts.
- Tor Browser processes (firefox.exe, tor.exe) were launched shortly after.
- A confirmed Tor control port connection (127.0.0.1:9151) proves Tor was running.
- Numerous Tor files were created on the Desktop, consistent with a portable Tor installation.
- A nonstandard file named “tor-shopping-list.txt” was created, implying user interaction beyond passive execution.

---

## Response Taken

TOR usage was confirmed on the endpoint `threat-hunt-lab` by the user `lamere`. The device was isolated and the user's direct manager was notified.

---
