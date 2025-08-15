# Threat Event (Unauthorized Chrome Extension Installation)
**Unauthorized Chrome Extension Installation - Unauthorized installation of a trojanized extension, with potential credential harvesting and data exfiltration**

## Steps the "Bad Actor" took Create Logs and IoCs:
1. Navigates to an unofficial Chrome extension repository: https://www.crx4chrome.com/
2. Searches for an unofficial extension
3. Downloads and saves the file: ```EIMADPBCBFNMBKOPOOJFEKHNKHDBIEEH_4_9_110_0.crx```
4. Loads the extension manually in Chrome Developer Mode: Go to chrome://extensions/
5. The extension appears to work normally. However, this trojanized copy includes code to capture credentials typed into forms.
6. A PowerShell script creates a file called ```SavedPasswords.txt``` with sensitive data (likely corporate usernames and passwords).

---

## Tables Used to Detect IoCs:
| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceProcessEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table |
| **Purpose**| Detects Chrome launch and PowerShell activity.  |

| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceFileEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicefileevents-table |
| **Purpose**| Detects files created in Downloads.  |

| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceNetworkEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicenetworkevents-table|
| **Purpose**| Detects connections to CRX4Chrome, CRX Extractor, or unexpected domains. |

---

## Related Queries:
```kql
// Sideloaded Chrome extensions (Developer Mode)
DeviceProcessEvents
| where DeviceName contains "W10"
| where FileName =~ "chrome.exe"
| project Timestamp, DeviceName, Account=InitiatingProcessAccountName, FileName, ProcessCommandLine
| order by Timestamp desc

// Extension Install Artifacts
DeviceFileEvents
| where DeviceName contains "W10"
| where FileName matches regex @"(?i)\.(crx|zip)$"
| project Timestamp, DeviceName, ActionType, FolderPath, FileName, InitiatingProcessFileName
| order by Timestamp desc

// Sensitive-looking file created in Downloads
DeviceFileEvents
| where FolderPath has @"\Downloads\"
| where FileName matches regex @"(?i)(password|passw|creds|credential|login|secrets).*"
| where ActionType == "FileCreated"
| project Timestamp, DeviceName, RequestAccountName, FolderPath, FileName, InitiatingProcessFileName

```

---

## Created By:
- **Author Name**: Ileana Villani
- **Author Contact**: https://www.linkedin.com/in/ileana-villani/
- **Date**: August 15, 2025

## Validated By:
- **Reviewer Name**: 
- **Reviewer Contact**: 
- **Validation Date**: 

---

## Additional Notes:
- **None**

---

## Revision History:
| **Version** | **Changes**                   | **Date**         | **Modified By**   |
|-------------|-------------------------------|------------------|-------------------|
| 1.0         | Initial draft                  | `August 15, 2025`  | `Ileana Villani`   
