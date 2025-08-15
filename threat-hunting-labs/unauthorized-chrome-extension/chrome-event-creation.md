# Threat Event (Unauthorized Chrome Extension Installation)
**Unauthorized Chrome Extension Installation - Unauthorized installation of a trojanized “Dark Reader” look-alike, with credential staging and simulated exfiltration**

## Steps the "Bad Actor" took Create Logs and IoCs:
1. Navigates to an unofficial Chrome extension repository: https://www.crx4chrome.com/
2. Searches for an unofficial extension: Dark Reader
3. Downloads and saves the file: ```EIMADPBCBFNMBKOPOOJFEKHNKHDBIEEH_4_9_110_0.crx```
4. Loads the extension manually in Chrome Developer Mode: Go to chrome://extensions/; Enable Developer Mode; Loaded the downloaded folder into the Extensions tab
5. The extension appears to work normally. However, this trojanized copy includes code to capture credentials typed into forms.
6. A PowerShell script creates a file called ```SavedPasswords.txt``` with sensitive data (corporate usernames and passwords)
7. The script makes a web request, exfiltrates the data and deletes the file.

---

## Tables Used to Detect IoCs:
| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceProcessEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table |
| **Purpose**| Detects Chrome launched with Developer Mode or ```--load-extension``` and PowerShell activity.  |

| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceFileEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicefileevents-table |
| **Purpose**| Detects files created in Downloads  |

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
| where FileName =~ "chrome.exe"
| where ProcessCommandLine has "--load-extension"
| project Timestamp, DeviceName, InitiatingProcessAccountName, ProcessCommandLine
| order by Timestamp desc

// Sensitive-looking file created in Downloads
DeviceFileEvents
| where FolderPath has @"\Downloads\"
| where FileName matches regex @"(?i)(password|passw|creds|credential|login|secrets).*"
| where ActionType == "FileCreated"
| project Timestamp, DeviceName, RequestAccountName, FolderPath, FileName, InitiatingProcessFileName

// Rapid create → delete (possible staging + cleanup)
let delete_window = 15m;
DeviceFileEvents
| where FileName matches regex @"(?i)(password|passw|creds|credential|login|secrets).*"
| summarize Created=minif(Timestamp, ActionType=="FileCreated"),
            Deleted=maxif(Timestamp, ActionType=="FileDeleted"),
            Creator=anyif(InitiatingProcessFileName, ActionType=="FileCreated"),
            Deleter=anyif(InitiatingProcessFileName, ActionType=="FileDeleted")
  by DeviceId, DeviceName, RequestAccountName, FileName, FolderPath
| extend Lifetime = Deleted - Created
| where isnotempty(Deleted) and Lifetime between (1s .. delete_window)
| order by Deleted desc

// Network to unofficial/lab domains near file activity
let window = 10m;
let sensitive =
DeviceFileEvents
| where FileName matches regex @"(?i)(password|passw|creds|credential|login|secrets).*"
| summarize FirstCreated=minif(Timestamp, ActionType=="FileCreated"),
            LastDeleted=maxif(Timestamp, ActionType=="FileDeleted")
  by DeviceId;
DeviceNetworkEvents
| where InitiatingProcessFileName in~ ("chrome.exe","powershell.exe")
| where RemoteUrl has_any ("crx4chrome.com","crxextractor.com","attacker-portal.net")
| join kind=inner sensitive on DeviceId
| where Timestamp between (FirstCreated - window .. LastDeleted + window)
| project Timestamp, DeviceName, InitiatingProcessFileName, RemoteUrl, RemoteIP, RemotePort
| order by Timestamp desc


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
