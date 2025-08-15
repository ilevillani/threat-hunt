# Threat Event (Unauthorized Chrome Extension Installation)
**Unauthorized Chrome Extension Installation and Use**

## Steps the "Bad Actor" took Create Logs and IoCs:
1. Navigates to an unofficial Chrome extension repository: https://www.crx4chrome.com/
2. Searches for an unofficial extension: Dark Reader
3. Downloads and saves the file: ```EIMADPBCBFNMBKOPOOJFEKHNKHDBIEEH_4_9_110_0.crx```
4. Loads the extension manually in Chrome Developer Mode: Go to chrome://extensions/; Enable Developer Mode; Loaded the downloaded folder into the Extensions tab
5. Created a file called ```Pass Book.txt``` with sensitive data (corporate usernames and passwords)
6. Deleted the file.

---

## Tables Used to Detect IoCs:
| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceProcessEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table |
| **Purpose**| Detects Chrome launched with Developer Mode or ```--load-extension```.  |

| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceNetworkEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicenetworkevents-table|
| **Purpose**| Detects connections to CRX4Chrome, CRX Extractor, or unexpected domains. |

---

## Related Queries:
```kql
// Detect Chrome launched with extension loading arguments
DeviceProcessEvents
| where FileName =~ "chrome.exe"
| where ProcessCommandLine has "--load-extension"
| project Timestamp, DeviceName, InitiatingProcessAccountName, ProcessCommandLine

// Detect extension folder creation in Chrome's profile
DeviceFileEvents
| where FolderPath has @"\Google\Chrome\User Data\Default\Extensions\"
| where ActionType in ("FileCreated","FolderCreated")
| project Timestamp, DeviceName, RequestAccountName, FolderPath, FileName, ActionType

// Detect SavedPasswords.txt creation or deletion
DeviceFileEvents
| where FileName contains "SavedPasswords.txt"
| project Timestamp, DeviceName, RequestAccountName, FileName, ActionType

// Detect network connections to CRX4Chrome or CRX Extractor
DeviceNetworkEvents
| where InitiatingProcessFileName =~ "chrome.exe"
| where RemoteUrl has_any ("crx4chrome.com","crxextractor.com")
| project Timestamp, DeviceName, InitiatingProcessAccountName, RemoteIP, RemotePort, RemoteUrl

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
