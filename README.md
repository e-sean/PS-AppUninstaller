# PS-AppUninstaller

**PowerShell toolkit to safely uninstall Windows apps with batch support, detailed logging, and exit code tracking for endpoint management solutions like SCCM/MECM and Intune.**

---

## 📋 Overview

`PS-AppUninstaller` is a PowerShell toolkit built for IT admins and endpoint engineers who want a **transparent, automation‑ready way to remove Windows applications**.  
It’s designed with enterprise workflows in mind: batch execution, audit‑friendly logs, and standardized exit codes that SCCM/MECM, Intune, and other management platforms can readily interpret.

Where this tool really shines:
- Removing rogue software that didn’t originate from an approved package  
- Cleaning up when a vendor’s MSI/EXE fails to fully uninstall  
- Removing corrupted installs where the `UninstallString` is no longer valid  
- Retiring software cleanly from the environment  
- Addressing Nexpose findings where vulnerabilities are flagged against partially‑installed software  

Key capabilities include:
- **Batch operations** via JSON configuration files  
- **Detailed transcript logging** for audit trails  
- **Standardized exit codes** for management software compatibility  
- **Support for multiple uninstall types**: MSI, EXE, AppX/MSIX, and App‑V  
- **Optional post‑uninstall cleanup**: shortcuts, registry keys, files, environment variables, PATH entries, scheduled tasks, services, certificates, and WMI  
- **Uninstall catalog**: a limited set of ready‑to‑use uninstall “recipes,” such as a full MECM client removal (useful when the client is corrupt and traditional repair/reinstall options don’t work)  

## ⚠️ Warning
- Testing so far has been limited to personal Windows 11 environments. While the toolkit is structured for enterprise scenarios, validate carefully in lab or pilot settings before broad deployment.  
- App‑V support is included in code but has **not yet been tested**. Evaluation on Windows 11 Enterprise is planned.

---

## ⚡ Quick Start

1. **Clone the repo**
   ```powershell
   git clone https://github.com/e-sean/PS-AppUninstaller.git
   cd PS-AppUninstaller
   ```
   Or download the ZIP, extract, and navigate to it.

2. Launch the script with -WhatIf to validate your -Name pattern. You may use wildcards `*` in your -Name pattern
   ```powershell
   .\Remove-App.ps1 -Name "*chrome*" -LN "Uninstall_GoogleChrome.log" -WhatIf
   ```
3. Refine your -Name pattern to make sure you're targeting the exact application you want removed. Populate any other parameters as needed and validate with another -WhatIf run
   ```powershell
   .\Remove-App.ps1 -Name "Google Chrome" -PN "chrome" -RA "/qn /norestart" -LN "Uninstall_GoogleChrome.log" -WhatIf
   ```
4. After validating the output, you're ready to test the removal with -WhatIf omitted.
   
5. Once you have successfully tested the removal, you can add this to an SCCM/MECM application, Intune package, or other endpoint manaagement solution.

---

## ❓ Usage

| Parameter       | Alias | Type     | Description                                                                 |
|-----------------|-------|----------|-----------------------------------------------------------------------------|
| `-Name`         |       | string   | DisplayName pattern (ARP), AppX package name, or Catalog key. Wildcards ok. |
| `-Arguments`    | `AR`  | string   | Extra uninstall arguments. Sanitized for EXE/MSI.                           |
| `-ProcessNames` | `PN`  | string[] | Processes to stop before uninstall.                                         |
| `-LogPath`      | `LP`  | string   | Directory for transcript logs (default: `C:\Temp\Logs`).                    |
| `-LogName`      | `LN`  | string   | Transcript log filename.                                                    |
| `-SuccessCodes` | `SC`  | int[]    | Additional success codes to map to 0.                                       |
| `-RebootCodes`  | `RC`  | int[]    | Additional reboot-success codes to map to 3010.                             |
| `-TimeoutSeconds` | `T` | int      | Max wait time for catalog process execution (default: 600).                 |
| `-AppV`         |       | switch   | Treat target as App‑V package.                                              |
| `-AppX`         |       | switch   | Treat target as AppX/MSIX package.                                          |
| `-ConfigPath`   | `CFG` | string   | Path to JSON configuration with one or more Apps.                           |
| `-Catalog`      |       | string   | Catalog key or `List` to show available key entries.                        |
| `-SkipUninstall`| `SU`  | switch   | Skip uninstall; run cleanup only.                                           |
| `-CleanupPolicy`|       | string   | `Strict` (default), `Lenient`, or `Always`. Controls when cleanup runs.     |
| `-WhatIf`       |       | switch   | Standard PowerShell WhatIf flag for previewing what the script will do.     |
| `-Verbose`      |       | string   | Standard PowerShell Verbose flag for additional details.                    |

<br>

| CleanupPolicy | Description                                                                                           |
|---------------|-------------------------------------------------------------------------------------------------------|
| `Strict`      | Default: Run cleanup IF the uninstall exit code indicates success (`0`) or success with reboot (`3010`). |
| `Lenient`     | Run cleanup if **any** uninstall step within the job succeeded (0 or 3010), even if others failed.       |
| `Always`      | Run cleanup **regardless** of uninstall result, including failures.                                     |

### Examples:
  Validate a match in ARP (Programs and Features) and preview uninstall:
  ```powershell
  .\Remove-App.ps1 -Name "*chrome*" -WhatIf
  ```
  
  Uninstall a single application registered in Programs and Features with all settings 
  contained in command line:
  ```powershell
  .\Remove-App.ps1 -Name "Google Chrome" -AR "/qn /norestart" -LN GoogleChrome_Uninstall.log
  ```
  
  Uninstall a single AppX/MSIX application and stop process(es) with all settings contained in command line:
  ```powershell
  .\Remove-App.ps1 -Name "Spotify*" -PN "spotify" -LN Spotify_Uninstall.log -AppX
  ```

  Uninstall one or more application(s) with all settings contained in JSON:
  ```powershell
  .\Remove-App.ps1 -ConfigPath .\Google_Chrome.json
  ```

  Use a catalog uninstall:
  ```powershell
  .\Remove-App.ps1 -Catalog List
  .\Remove-App.ps1 -Catalog "Chrome_Enterprise" -LN GoogleChrome_Enterprise_Uninstall.log
  ```

  Run a catalog cleanup only (skip uninstall):
  ```powershell
  .\Remove-App.ps1 -Catalog "Chrome_StandaloneUser" -LN GoogleChrome_StandaloneUser_Uninstall.log -SU -CleanupPolicy Always
  ```

---

## ℹ️ Sample JSON App Templates
JSON configured to stop any Chrome processes, silently remove a single app "Google Chrome" (Standalone non-MSI version which returns exit code 19 if successful), delete all shortcuts containing "Google Chrome" from all common user directories, and delete the user data directory left behind after uninstall.
```json
{
  "Apps": [
    {
      "_Comment": "Google Chrome (Standalone)",
      "Name": "Google Chrome",
      "Arguments": "--force-uninstall",
      "ProcessNames": [
        "chrome"
      ],
      "SuccessCodes": [
        19
      ],
      "RebootCodes": [],
      "LogPath": "",
      "LogName": "Uninstall_GoogleChromeStandalone.log",
      "AppV": false,
      "AppX": false,
      "Cleanup": {
        "Shortcuts": [
          {
            "Name": "Google Chrome",
            "Lnk": true,
            "Url": false,
            "StartMenu": false,
            "Desktop": false,
            "Documents": false,
            "RemoveAll": true
          }
        ],
        "RegistryKeys": [],
        "FilePaths": [
          "%LOCALAPPDATA%\\Google\\Chrome\\User Data"
        ],
        "EnvironmentVariables": [],
        "PathEntries": [],
        "Certificates": [],
        "ScheduledTasks": [],
        "Services": [],
        "WMI": {
          "Classes": [],
          "Namespaces": []
        }
      }
    }
  ]
}
```

JSON configured to silently remove both the 32-bit and 64-bit versions of JRE 8 Update 461
```json
{
  "Apps": [
    {
      "_Comment": "MSI uninstall for Java 8 Update 461 64-bit",
      "Name": "Java 8 Update 461 (64-bit)",
      "Arguments": "/qn /norestart",
      "ProcessNames": [],
      "SuccessCodes": [],
      "RebootCodes": [],
      "LogPath": "",
      "LogName": "Java_8u461_64bit_Uninstall.log",
      "AppV": false,
      "AppX": false,
      "Cleanup": {
        "Shortcuts": [
          {
            "Name": "",
            "Lnk": true,
            "Url": false,
            "StartMenu": false,
            "Desktop": true,
            "Documents": false,
            "RemoveAll": true
          }
        ],
        "RegistryKeys": [],
        "FilePaths": [],
        "EnvironmentVariables": [],
        "PathEntries": [],
        "Certificates": [],
        "ScheduledTasks": [],
        "Services": [],
        "WMI": {
          "Classes": [],
          "Namespaces": []
        }
      }
    },
    {
      "_Comment": "MSI uninstall for Java 8 Update 461 32-bit",
      "Name": "Java 8 Update 461",
      "Arguments": "/qn /norestart",
      "ProcessNames": [],
      "SuccessCodes": [],
      "RebootCodes": [],
      "LogPath": "",
      "LogName": "Java_8u461_32bit_Uninstall.log",
      "AppV": false,
      "AppX": false,
      "Cleanup": {
        "Shortcuts": [
          {
            "Name": "",
            "Lnk": true,
            "Url": false,
            "StartMenu": false,
            "Desktop": true,
            "Documents": false,
            "RemoveAll": false
          }
        ],
        "RegistryKeys": [],
        "FilePaths": [],
        "EnvironmentVariables": [],
        "PathEntries": [],
        "Certificates": [],
        "ScheduledTasks": [],
        "Services": [],
        "WMI": {
          "Classes": [],
          "Namespaces": []
        }
      }
    }
  ]
}
```

JSON App Template Explained
```json
{
  "Apps": [
    {
      "_Comment": "",               //Add a description that you will understand.
      "Name": "",                   //Name of application to search for and uninstall. Supports wildcards (*).
      "Arguments": "",              //Any arguments to pass with the uninstall command.
      "ProcessNames": [],           //Process names that will be closed prior to uninstall.
      "SuccessCodes": [],           //Non-standard success exit codes that will be converted to 0 if encountered.
      "RebootCodes": [],            //Non-standard success (reboot required) exit codes that will be converted to 3010 if encountered.
      "LogPath": "",                //Path to logs if not using default (C:\temp\Logs).
      "LogName": "",                //Name of log file to be generated for this app removal.
      "AppV": false,                //Indicates that our target app is AppV based.
      "AppX": false,                //Indicates that our target app is AppX/MSIX based.
      "Cleanup": {          //Cleanup section where we can optionally remove items leftover after the uninstall.
        "Shortcuts": [          //Shortcut cleanup section.
          {
            "Name": "",             //Name of shortcut to delete. Supports wildcards (*).
            "Lnk": true,            //Indicate if shortcut is an lnk file.
            "Url": false,           //Indicate if shortcut is a URL file.
            "StartMenu": false,     //Delete shortcut file from Start Menu for all users. Will not touch pinned items.
            "Desktop": false,       //Delete shortcut file from the Desktop of all users.
            "Documents": false,     //Delete shortcut file from the Documents folder of all users.
            "RemoveAll": true       //Delete shortcut file from Start Menu, Desktop, and Documents folders of all users.
          }
        ],
        "RegistryKeys": [],         //Delete registry key(s).
        "FilePaths": [],            //Delete file path(s). Supports environment variable expansion through %% tokens (like %APPDATA%).
        "EnvironmentVariables": [], //Delete environment variables. Protects common system default env variables.
        "PathEntries": [],          //Remove an entry from the system path environment variable.
        "Certificates": [],         //Delete a certificate from all stores. Must list the thumbprint of each cert to delete.
        "ScheduledTasks": [],       //Delete a scheduled task. Supports wildcard * searches. Use caution.
        "Services": [],             //Remove a registered service.
        "WMI": {               //WMI cleanup section
          "Classes": [],            //Delete a WMI class. Protects common system classes.
          "Namespaces": []          //Delete a WMI namespace. Protects common system namespaces.
        }
      }
    }
  ]
}
```
