# 🛡️ Threat Hunting Scenario: Suspected Data Exfiltration from PIPd Employee

## Overview

An employee named John Doe, working in a sensitive department, recently got put on a performance improvement plan (PIP). After John threw a fit, management has raised concerns that John may be planning to steal proprietary information and then quit the company. Your task is to investigate John's activities on his corporate device (windows-target-1) using Microsoft Defender for Endpoint (MDE) and ensure nothing suspicious is taking place.

## 🔍 1. Preparation

**🎯 Goal:** Set up the hunt by defining what you're looking for.

**Activity:** John is an administrator on his device and is not limited on which applications he uses. He may try to archive/compress sensitive information and send it to a private drive or something.

## 📥 2. Data Collection

**🎯 Goal:** Gather relevant data from logs, network traffic, and endpoints.

**Activity:** Ensure data is available from all key sources for analysis.
Relevant tables contain recent logs for virtual machine:
- `DeviceFileEvents`
- `DeviceProcessEvents`
- `DeviceNetworkEvents`

I did a search within MDE **DeviceFileEvents** for any activities with zip files, and found a lot of regular activity of archiving stuff and moving to a **“backup”** folder.

```kql
DeviceFileEvents
| where DeviceName == "windows-target-1"
| where FileName endswith ".zip"
| order  by Timestamp desc

```
**Results:**
![image](https://github.com/user-attachments/assets/18162bc5-14ef-447d-a093-d555c8574365)


## 🔍 3. Data Analysis
**🎯 Goal:** Confirm suspicious behavior by testing the hypothesis.

I took one of the instances of a zip file being created, took the timestamp and searched under **DeviceProcessEvents** for anything happening 2 minutes before the archive was created and 2 minutes after. I discovered around the same time, a powershell script silently installed 7zip and then used 7zip to zip up employee data into archive:

```kql
let specificTime = datetime(2025-06-09T16:49:53.7431574Z);
let VMName = "windows-target-1";
DeviceProcessEvents
| where Timestamp between ((specificTime - 2m) .. (specificTime + 2m))
| where DeviceName == VMName
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, InitiatingProcessCommandLine

```

**Results:**
![image](https://github.com/user-attachments/assets/6ccdc872-ca3b-416d-821c-121beef61bbe)


I searched around the same time period for any evidence of exfiltration from the network, but I didn’t see any logs indicating as such:

```kql
let specificTime = datetime(2025-06-09T16:49:53.7431574Z);
let VMName = "windows-target-1";
DeviceNetworkEvents
| where Timestamp between ((specificTime - 2m) .. (specificTime + 2m))
| where DeviceName == VMName
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType

```

## 🕵️‍♂️ 4.  Investigation
**🎯 Goal:** Validate findings and map behavior to attacker TTPs.

#### ✅ Identified MITRE ATT&CK TTPs

#### 1. [T1059.001 – PowerShell](https://attack.mitre.org/techniques/T1059/001/)
- **Tactic**: Execution  
- **Why**: The attacker/script used PowerShell to install 7-Zip silently, indicating script-based command execution.  
- **Source**:  
  > "...a PowerShell script silently installed 7zip..."

#### 2. [T1218.005 – Signed Binary Proxy Execution: Msiexec](https://attack.mitre.org/techniques/T1218/005/) *(if msiexec or similar was used)*
- **Tactic**: Defense Evasion, Execution  
- **Why**: If the installation of 7-Zip was done using a signed installer (like `msiexec`), this technique applies. Otherwise, disregard this.

#### 3. [T1560.001 – Archive Collected Data: Archive via Utility](https://attack.mitre.org/techniques/T1560/001/)
- **Tactic**: Collection  
- **Why**: 7-Zip was used to archive employee data into `.zip` format.  
- **Source**:  
  > "...used 7zip to zip up employee data into archive..."

#### 4. [T1074.001 – Data Staged: Local Data Staging](https://attack.mitre.org/techniques/T1074/001/)
- **Tactic**: Collection  
- **Why**: The `.zip` files were stored in a "backup" folder on the local system.  
- **Source**:  
  > "...moving to a 'backup' folder..."

#### 5. [T1005 – Data from Local System](https://attack.mitre.org/techniques/T1005/) *(Potentially)*
- **Tactic**: Collection  
- **Why**: The script collected employee data (unspecified which files exactly) before archiving.

#### ❌ No Evidence of Exfiltration Found (But Still Consider Monitoring)

#### ⚠️ [T1041 – Exfiltration Over C2 Channel](https://attack.mitre.org/techniques/T1041/) / [T1048 – Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048/)
- **Tactic**: Exfiltration  
- **Why**: You specifically investigated this but found no evidence.  
- **Source**:  
  > "...searched for any evidence of exfiltration...didn’t see any logs..."

**Note**: Continue monitoring — exfiltration may be time-delayed or done manually.

### 🛡️ Summary Table of Mapped MITRE ATT&CK TTPs

| Tactic         | Technique ID | Technique Name                                      |
|----------------|--------------|-----------------------------------------------------|
| Execution      | T1059.001    | [PowerShell](https://attack.mitre.org/techniques/T1059/001/)                      |
| Collection     | T1560.001    | [Archive Collected Data: Archive via Utility](https://attack.mitre.org/techniques/T1560/001/) |
| Collection     | T1074.001    | [Data Staged: Local Data Staging](https://attack.mitre.org/techniques/T1074/001/) |
| Collection     | T1005        | [Data from Local System](https://attack.mitre.org/techniques/T1005/)             |
| Defense Evasion (Potential) | T1218.005    | [Signed Binary Proxy Execution: Msiexec](https://attack.mitre.org/techniques/T1218/005/) |
| Exfiltration (Investigated) | T1041 / T1048 | [Exfiltration Over C2 / Alternative Protocol](https://attack.mitre.org/techniques/T1041/), [T1048](https://attack.mitre.org/techniques/T1048/) |

## ✅ 5. Response

**Goal:** Mitigate any confirmed threats  
**Activity:** Work with security teams to contain, remove, and recover from the threat

### ✔️ Actions Taken / Recommendations:

- **Containment:**
  - Isolate the affected endpoint if activity resumes.
  - Monitor similar endpoints for the same behavior.

- **Removal:**
  - Delete unauthorized scripts.
  - Uninstall 7-Zip if not company-approved.
  - Investigate how 7-Zip was installed (e.g., via `msiexec` or direct execution).

- **Recovery:**
  - Verify integrity of affected employee data.
  - Reset credentials if compromise is suspected.
  - Ensure backups are secure and untouched.

- **Preventative Measures:**
  - Enforce app allowlisting to prevent unapproved installs.
  - Limit PowerShell use to signed scripts.
  - Monitor archiving tools for use on sensitive data.

## 📚 6. Documentation

**Goal:** Record your findings and learn from them  
**Activity:** Document what you found and use it to improve future hunts and defenses

### 🧾 Summary of Findings:

- PowerShell used to silently install 7-Zip.
- Employee data archived into `.zip` files.
- Files stored in a local `backup` folder.
- Activity repeated over time — not a one-time event.
- No outbound network activity suggesting data exfiltration.

### 🔍 Artifacts Collected:

- `DeviceFileEvents`, `DeviceProcessEvents`, and `DeviceNetworkEvents` logs
- Timestamps for script and file operations
- MITRE ATT&CK mapping

### 🪪 Next Steps:

- Retain logs and findings in a case file
- Share results with management and SOC
- Document this use case to train future analysts

## 🔄 7. Improvement

**Goal:** Improve your security posture or refine your methods for the next hunt  
**Activity:** Adjust strategies and tools based on what worked or didn’t

### 🔐 Prevention Recommendations:

- **App Control:** Block unauthorized installers like 7-Zip using allowlisting.
- **Script Controls:** Restrict and monitor PowerShell use via GPO and logging.
- **Data Controls:** Label employee data and set alerts for unauthorized access.
- **Behavioral Analytics:** Deploy UEBA to spot unusual archiving or automation behavior.

### 🔧 Hunting Process Improvements:

- **Expand Time Ranges:** Use wider timeframes (±5–10 mins) in future hunts.
- **Automate Detection:** Create rules to flag archiving tools accessing sensitive files.
- **Correlate Identity Logs:** Tie script activity back to user accounts and session data.

---

📌 **Conclusion:**  
While no exfiltration was confirmed, this hunt uncovered suspicious and potentially malicious data staging behavior. By documenting, responding, and improving from this case, your team is now better equipped to detect and mitigate future insider threats or data leakage risks.
