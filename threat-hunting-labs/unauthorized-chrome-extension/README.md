# Threat Hunt Report: Unauthorized Chrome Extension – Dark Reader

<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Darkreader Logo"/>

- [Scenario Creation](https://github.com/ilevillani/threat-hunt/blob/main/threat-hunting-labs/unauthorized-chrome-extension/chrome-event-creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Chrome Browser

##  Scenario

Management suspects that some employees may be bypassing Chrome Web Store restrictions to install unapproved extensions.
Recent industry reports highlighted malicious trojanized versions of Dark Reader—a popular dark mode extension—that were altered to log credentials and send them to attacker-controlled infrastructure.
The goal is to detect sideloaded Chrome extensions, identify any credential staging files, and determine whether they were quickly removed (indicating anti-forensics).

### High-Level Dark Reader Impersonation IoC Discovery Plan

- **Check `DeviceProcessEvents`** for any `chrome(.exe)` launched with `--load-extension` (Developer Mode sideload).
- **Check `DeviceFileEvents`** for suspicious file creation in Downloads (`SavedPasswords.txt`).
- **Check `DeviceFileEvents`** for rapid creation → deletion within minutes.
- **Check `DeviceNetworkEvents`** for connections to known unofficial sources and lab domains.

---

## Steps Taken

### 1. Searched the `DeviceProcessEvents` Table

Searched for any file that had the string "chrome" in it and discovered what looks like the user "pavel" downloaded Chrome and did something that triggered Chrome sandboxed unzip utility — commonly triggered when unpacking a CRX/ZIP (fits extension sideload) at `2025-08-15T17:51:56.1453334Z`.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName contains "W10"
| where FileName =~ "chrome.exe"
| project Timestamp, DeviceName, Account=InitiatingProcessAccountName, FileName, ProcessCommandLine
| order by Timestamp desc
```
<img width="1212" alt="image" src="<img width="1192" height="245" alt="image" src="https://github.com/user-attachments/assets/0e38d220-d8c1-4d1e-989c-e1114d8185a5" />">

---

### 2. Searched the `DeviceProcessEvents` Table

Searched for any `FileName` that contained the string "crx" or "zip". Based on the logs returned, at `2025-08-15T18:12:04.1419221Z`, an employee on the "W10-Gdansk" device downloaded the file `EIMADPBCBFNMBKOPOOJFEKHNKHDBIEEH_4_9_110_0.crx`. This appears first in the temp files and appears as `FileCreated`. Then, at `2025-08-15T18:19:17.3745482Z` the final artifact was created in the Downloads folder, showing up as `FileRenamed` in the logs.

**Query used to locate event:**

```kql

DeviceFileEvents
| where DeviceName contains "W10"
| where FileName matches regex @"(?i)\.(crx|zip)$"
| project Timestamp, DeviceName, ActionType, FolderPath, FileName, InitiatingProcessFileName
| order by Timestamp desc
```
<img width="1214" height="281" alt="image" src="https://github.com/user-attachments/assets/35264075-de18-408a-83df-3fc1a7eb9bd7" />

<img width="1053" height="235" alt="image" src="https://github.com/user-attachments/assets/f465374d-0b38-4046-87c7-e580ed0704ef" />


---

### 3. Searched the `DeviceFileEvents` Table for any evidence of sensitive data being saved on the local machine

Searched for any indication that text files with sensitive data were being saved on the local machine. There was evidence that a file `SavedPasswords.txt` was created at `2025-08-15T18:51:14.5910126Z`. The process was initiated by a PowerShell script.

**Query used to locate events:**

```kql
DeviceFileEvents
| where FolderPath has @"\Downloads\"
| where FileName matches regex @"(?i)(password|passw|creds|credential|login|secrets).*"
| where ActionType == "FileCreated"
| project Timestamp, DeviceName, RequestAccountName, FolderPath, FileName, InitiatingProcessFileName
```
<img width="1262" height="288" alt="image" src="https://github.com/user-attachments/assets/035dabff-01e4-433b-a18b-ab391242cc88" />


---

### 4. Searched the `DeviceNetworkEvents` Table Network Connections (Data Exfiltration) and `DeviceProcessEvents` for evidence of file deletion

After the suspicious extension sideload and creation of a sensitive-looking file (SavedPasswords.txt) I searched for any indication of cleanup commands execution or data exfiltration. While Microsoft Defender for Endpoint did not log a direct FileDeleted event in this environment (a known telemetry gap when deletions occur via PowerShell or in OneDrive-synced folders), there is corroborating evidence that strongly suggests this action may have occurred. File Creation (SavedPasswords.txt) was observed, initiated by powershell.exe. No subsequent access to this file after simulated “exfiltration,” consistent with attacker clean-up.

---

## Chronological Event Timeline 

### 1. Chrome Process Activity – Extension Unpack

- **Timestamp:** `2025-08-15T17:51:56.1453334Z`
- **Event:** The user "pavel" on device `W10-Gdansk` launched `chrome.exe`. A sandboxed utility process named `--type=utility --utility-sub-type=unzip.mojom.Unzipper` executed.
- **Action:** Indicates Chrome was unpacking a CRX/ZIP archive, consistent with sideloading an extension.
- **File Path:** `chrome.exe` (unzip utility mode).

### 2. Extension File Download – Dark Reader CRX

- **Timestamp:** `2025-08-15T18:12:04.1419221Z`
- **Event:** File `EIMADPBCBFNMBKOPOOJFEKHNKHDBIEEH_4_9_110_0.crx` created in a Chrome temp directory.
- **Action:** File creation detected. This is the identifier for Dark Reader (official ID), but its sideload via CRX file instead of Chrome Web Store raises concerns of tampering.
- **File Path:** `C:\Program Files\Google\Chrome\Temp\...`

### 3. Extension Artifact Finalization – Moved to Downloads

- **Timestamp:** `2025-08-15T18:19:17.3745482Z`
- **Event:** The CRX file appeared in the user’s Downloads directory as a `FileRenamed` event.
- **Action:** Indicates Chrome moved the unpacked extension from temp to permanent storage.
- **File Path:** `C:\Users\pavel\Downloads\EIMADPBCBFNMBKOPOOJFEKHNKHDBIEEH_4_9_110_0.crx`

### 4. Credential File Created

- **Timestamp:** `2025-08-15T18:51:14.5910126Z`
- **Event:** File `SavedPasswords.txt` was created in the user’s Downloads folder.
- **Action:** File creation detected. This file contained dummy credentials and was created by a PowerShell script, simulating attacker credential harvesting.
- **Initiating Process:** `powershell.exe`
- **File Path:** `C:\Users\pavel\Downloads\SavedPasswords.txt`

---

## Summary

The user bypassed Chrome Web Store restrictions and sideloaded the Dark Reader extension manually via `.crx`. A suspicious staging file (SavedPasswords.txt) containing credentials was created in the same Downloads folder. The absence of a FileDeleted log highlights a telemetry limitation, but process evidence suggests attacker-like cleanup.
The absence of a delete event should not be considered a false negative. The attacker sideloaded an unauthorized Chrome extension, stored sensitive data locally which was then likely exfiltrated, and cleaned up to avoid forensic investigations.

---

## Response Taken

Unauthorised Chrome extension download was confirmed on the endpoint `W10-Gdansk` by the user `pavel`. The device was isolated, and the user's direct manager was notified.

---
