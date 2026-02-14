# 🛡 Windows Detection Lab using Splunk (Home SOC Project)

## 📌 Project Overview

This project demonstrates the design and implementation of a **home SOC-style detection lab** using:

* **Windows 11**
* **Splunk Enterprise**
* **Splunk Universal Forwarder**
* **Native Windows Security Event Logging**

The objective was to simulate real-world attacker techniques, ingest endpoint telemetry into a SIEM, and develop detection rules mapped to the **MITRE ATT&CK framework**.

---

## 🏗 Lab Architecture

**Components:**

* Windows 11 Host (Log Source)
* Splunk Enterprise (SIEM)
* Splunk Universal Forwarder (Log Ingestion Agent)
* Windows Security Event Logs (Primary Data Source)

**Logs Collected:**

* Security Event Logs
* Process Creation Events (Event ID 4688)
* Authentication Events
* Account Management Events

---

## ⚙ Configuration & Hardening Steps

### 1️⃣ Splunk Deployment

* Installed **Splunk Enterprise** on Windows 11
* Installed and configured **Splunk Universal Forwarder**
* Configured forwarding of:

  * `WinEventLog:Security`
  * `WinEventLog:Application`

**Verified ingestion using:**

```spl
index=*
```

---

### 2️⃣ Enabled Advanced Audit Policies

#### ✅ Enabled Process Creation Logging

```powershell
auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable
```

**Verification:**

```powershell
auditpol /get /subcategory:"Process Creation"
```

---

#### ✅ Enabled Command-Line Logging (Enhanced Visibility)

```powershell
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f
gpupdate /force
```

System reboot performed to apply changes.

---

# 🔍 Detection Engineering

The following detections were developed and tested.

---

## 🔐 1. Failed Logon Detection

* **Event ID:** 4625
* **MITRE ATT&CK:** T1110 – Brute Force

### Query

```spl
EventCode=4625
```

### Purpose

Detects failed authentication attempts that may indicate:

* Brute force attacks
* Password spraying

---

## 👤 2. Account Creation Detection

* **Event ID:** 4720
* **MITRE ATT&CK:** T1136 – Create Account

### Query

```spl
EventCode=4720
```

### Test Method

```powershell
net user testuser123 P@ssw0rd! /add
```

### Purpose

Detects creation of new local accounts that may indicate persistence mechanisms.

---

## 🔑 3. Privileged Logon Detection

* **Event ID:** 4672
* **MITRE ATT&CK:** T1078 – Valid Accounts

### Query

```spl
EventCode=4672
```

### Purpose

Detects logons using accounts with elevated privileges.

---

## 🖥 4. PowerShell Execution Detection

* **Event ID:** 4688
* **MITRE ATT&CK:** T1059.001 – PowerShell

### Basic Query

```spl
index=* EventCode=4688 "powershell.exe"
```

### Enhanced Detection Query

```spl
sourcetype=WinEventLog:Security EventCode=4688
| search New_Process_Name="*powershell*"
| table _time ComputerName Account_Name New_Process_Name CommandLine
| sort -_time
```

### Test Commands

```powershell
whoami
Get-Process
powershell -EncodedCommand <test_payload>
```

### Purpose

Detects PowerShell execution commonly used in:

* Post-exploitation
* Malware staging
* Living-off-the-land techniques

---

# 🚨 Alerting

Each detection was converted into a **scheduled Splunk alert** with:

* **Trigger Condition:** Number of results > 0
* **Schedule:** Every 5 minutes
* **Action:** Logged to Triggered Alerts

This simulates SOC-style automated monitoring.

---

# 📊 Monitoring Dashboard

A custom Splunk dashboard was created titled:

> **Windows Host Monitoring Dashboard**

### Dashboard Panels:

* Failed Logons (4625)
* PowerShell Executions (4688)
* Account Creations (4720)
* Privileged Logons (4672)

index=* sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| search Image="*powershell.exe"
| table _time Computer User ParentImage CommandLine


