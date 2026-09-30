# Threat-Hunt-Report---Meridian
---

## 📌 Executive Summary

An external attacker (10.1.134.57) compromised a single internet-facing Ubuntu host running the Meridian healthcare portal (Apache/PHP/MySQL) between 02:42 and 05:30 UTC on 2026-02-06. The intrusion followed a classic single-host chain: multi-tool web recon, a path-traversal flaw in an authenticated endpoint used to read `/etc/passwd` and `database.conf`, credential reuse to log in over SSH as `svc_backup`, privilege escalation through a planted SUID root shell, and a second, better-hidden SUID backdoor that established outbound C2 to the attacker. A six-service automated defence stack ran throughout, and the core analytic challenge was separating real intrusion artefacts from the stack's own bootstrap noise and remediation. The stack fixed some artefacts automatically but only *logged* the second backdoor (`/opt/meridian/scripts/health_check`), which was still running as root when a human responder captured memory. The incident is **not contained**: the live backdoor process must still be terminated manually.

---

## 🎯 Hunt Objectives

- Identify malicious activity across web, auth, audit, network, and database telemetry
- Separate genuine attacker artefacts from the automated defence stack's self-generated noise
- Correlate attacker behavior to MITRE ATT&CK techniques
- Document evidence, detection gaps, and the outstanding response action

---

## 🧭 Scope & Environment

- **Environment:** Single Ubuntu 22.04 host, `ip-10-1-15-67` (10.1.15.67), running Apache, PHP, and MySQL behind the Meridian patient portal; a six-service automated defence stack (`/opt/defender/*_monitor.sh`) active throughout
- **Data Sources:** `MeridianAccess_CL`, `MeridianAudit_CL`, `MeridianAuth_CL`, `MeridianDefender_CL`, `MeridianSyslog_CL`, `MeridianSnapshot_CL`, `MeridianNetwork_CL`, `MeridianMySQL_CL` (Log Analytics workspace `LAW-HuntPractice`)
- **Attacker:** 10.1.134.57
- **Timeframe:** 2026-02-06 02:42 → 05:30 UTC (~3 hours)

> **Analytic note on time:** all queries filter and order by `EventTime_t` (true event time), never `TimeGenerated` (ingestion time), and exclude rows where `EventTime_t` is empty. `MeridianSnapshot_CL` and `MeridianNetwork_CL` are point-in-time captures with no `EventTime_t` and are queried on structure, not time.

---

## 📚 Table of Contents

- [🧠 Hunt Overview](#-hunt-overview)
- [🧬 MITRE ATT&CK Summary](#-mitre-attck-summary)
- [🔍 Section Analysis](#-section-analysis)
  - [🧩 Section 1 — The Opening Scan](#-section-1--the-opening-scan)
    - [🚩 1.1 The Recon Playbook](#-flag-1-1)
  - [🧩 Section 2 — Initial Access](#-section-2--initial-access)
    - [🚩 2.1 The Traversal Point](#-flag-2-1)
    - [🚩 2.2 What They Pulled](#-flag-2-2)
  - [🧩 Section 3 — Borrowed Access](#-section-3--borrowed-access)
    - [🚩 3.1 Borrowed Access](#-flag-3-1)
    - [🚩 3.2 The Road Not Taken](#-flag-3-2)
  - [🧩 Section 4 — The Planted Root Shell](#-section-4--the-planted-root-shell)
    - [🚩 4.1 The Planted Root Shell](#-flag-4-1)
  - [🧩 Section 5 — Persistence](#-section-5--persistence)
    - [🚩 5.1 The Second Foothold](#-flag-5-1)
    - [🚩 5.2 Why It Survived](#-flag-5-2)
  - [🧩 Section 6 — Calling Home](#-section-6--calling-home)
    - [🚩 6.1 Calling Home](#-flag-6-1)
    - [🚩 6.2 What the Block Proves](#-flag-6-2)
  - [🧩 Section 7 — Collection](#-section-7--collection)
    - [🚩 7.1 What Left the Database](#-flag-7-1)
    - [🚩 7.2 The Tampered File](#-flag-7-2)
  - [🧩 Section 8 — Defence Evasion & Detection Gaps](#-section-8--defence-evasion--detection-gaps)
    - [🚩 8.1 Signal or Setup Noise](#-flag-8-1)
    - [🚩 8.2 Collateral Damage](#-flag-8-2)
  - [🧩 Section 9 — Response](#-section-9--response)
    - [🚩 9.1 Capturing the Evidence](#-flag-9-1)
    - [🚩 9.2 What's Still Live](#-flag-9-2)
- [🚨 Detection Gaps & Recommendations](#-detection-gaps--recommendations)
- [🧾 Final Assessment](#-final-assessment)
- [📎 Analyst Notes](#-analyst-notes)

---

## 🧠 Hunt Overview

The attacker began with a one-second root SSH login from their own IP at **02:48:41** — an unexplained event that predates the main intrusion and is the most likely (but unproven) staging window for later tooling. The host then rebooted at **03:23**, and the defence stack's own installation generated a burst of "SSH key / crontab / new systemd service" detections (02:53:31) and an early sweep (03:08) that removed legitimate Sysmon tooling. None of that early noise correlates with an active attacker session.

The real intrusion started at **03:47:32** with an nmap service scan, followed by manual `curl`, WhatWeb fingerprinting, and a 18k-request gobuster brute force. The attacker authenticated to the web app (SQLi-style bypass on `/index.php`), then abused a path-traversal flaw in `config_viewer.php?file=` to read `/etc/passwd` and `database.conf`. Credentials from that config let them SSH in as `svc_backup` at **04:09:31**. A denied `sudo -l` and failed root password logins were dead ends; escalation instead came through a pre-planted SUID binary `/tmp/rootbash -p` at **04:40:15**. The attacker then planted a stealthier SUID backdoor, `/opt/meridian/scripts/health_check`, which ran as root, spawned shells, and beaconed to `10.1.134.57:43212`.

The defence stack blocked the outbound traffic 73 times and, in its final sweep (05:05), killed the `/tmp/rootbash` process, reverted keys/crontabs/`backup.conf`, and cleaned `/tmp` — but only *logged* `health_check` as a non-baseline file. A responder (`ubuntu`, from 10.0.2.139) returned at 05:22, captured memory twice with AVML, but the backdoor process was still alive at end of window.

---

## 🧬 MITRE ATT&CK Summary

| Section | Question | Technique Category | MITRE ID | Priority |
|:-------:|----------|-------------------|----------|----------|
| 1 | 1.1 Recon Playbook | Active Scanning | T1595 | Medium |
| 2 | 2.1 Traversal Point | Exploit Public-Facing Application | T1190 | High |
| 2 | 2.2 What They Pulled | Credentials In Files / Path Traversal | T1552.001 | High |
| 3 | 3.1 Borrowed Access | Valid Accounts | T1078 | High |
| 3 | 3.2 Road Not Taken | Abuse Elevation Control (failed) / Valid Accounts | T1548 / T1078 | Medium |
| 4 | 4.1 Planted Root Shell | Setuid and Setgid | T1548.001 | High |
| 5 | 5.1 Second Foothold | Masquerading: Match Legitimate Name or Location | T1036.005 | High |
| 5 | 5.2 Why It Survived | Hidden Artifacts / remediation-scope gap | T1564.001 | High |
| 6 | 6.1 Calling Home | Application Layer Protocol (C2) | T1071 | High |
| 6 | 6.2 What the Block Proves | Application Layer Protocol (C2 containment) | T1071 | High |
| 7 | 7.1 What Left the Database | Data from Information Repositories | T1213 / T1005 | Critical |
| 7 | 7.2 Tampered File | Stored Data Manipulation | T1565.001 | Medium |
| 8 | 8.1 Signal or Setup Noise | Bootstrap noise (defensive analysis, non-attributable) | — | Low |
| 8 | 8.2 Collateral Damage | Impair Defenses: Disable or Modify Tools | T1562.001 | High |
| 9 | 9.1 Capturing the Evidence | Memory acquisition (incident response) | — | Info |
| 9 | 9.2 What's Still Live | Masquerading / outstanding containment | T1036 | Critical |

---

## 🔍 Section Analysis

_All questions below are collapsible for readability._

---

### 🧩 Section 1 — The Opening Scan

<details>
<summary id="-flag-1-1">🚩 <strong>1.1 The Recon Playbook</strong></summary>

### 🎯 Objective
Map the web server with automated tooling before touching anything sensitive.

### 📌 Finding
**Answer: 4 — nmap, curl, whatweb, gobuster.** Four distinct recon tools hit the server from 10.1.134.57, each with its own user-agent signature, in a methodical sequence. nmap scanned ports/services, curl manually checked the web root and `robots.txt`, WhatWeb fingerprinted the stack, and gobuster brute-forced directories (18,454 requests, 18,434 × 404, leaving ~20 discovered paths).

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | ip-10-1-15-67 |
| Source | 10.1.134.57 |
| nmap (`Nmap Scripting Engine`) | first seen 03:47:32 |
| curl (`curl/8.18.0`) | first seen 03:52:09 |
| whatweb (`WhatWeb/0.6.3`) | first seen 03:54:54 |
| gobuster (`gobuster/3.8.2`) | first seen 03:55:05 (18,454 req) |

> The empty (`-`) user-agent that appears at 03:47:32 is nmap's raw service-detection probes (no UA header), not a distinct fifth tool.

### 💡 Why it matters
The tool sequence reveals a deliberate recon-then-exploit methodology. It also fixes the moment the defence stack woke up: its first detection (03:55:05) coincides exactly with gobuster, meaning nmap, WhatWeb, and the first three minutes of curl went unflagged.

### 🔧 KQL Query Used
```kql
MeridianAccess_CL
| where isnotempty(EventTime_t)
| where ClientIp_s == "10.1.134.57"
| summarize FirstSeen=min(EventTime_t), LastSeen=max(EventTime_t), Requests=count(),
            NotFound=countif(StatusCode_s == "404"), SampleUri=take_any(RequestUri_s) by UserAgent_s
| order by FirstSeen asc
```

### 🖼️ Screenshot
<Insert screenshot>

### 🛠️ Detection Recommendation

**Hunting Tip:**
Summarize by `UserAgent_s` per source IP and alert on multiple known scanner signatures from one address within a short window. High 404-to-200 ratios (gobuster: 18,434/18,454) are a strong directory-brute-force indicator.

</details>

---

### 🧩 Section 2 — Initial Access

<details>
<summary id="-flag-2-1">🚩 <strong>2.1 The Traversal Point</strong></summary>

### 🎯 Objective
Identify the single endpoint the attacker deliberately targeted before the mass scan — their way in.

### 📌 Finding
**Answer: `config_viewer.php`.** Before gobuster started, the attacker read `/robots.txt` (03:52:21) and 8 seconds later requested `/config_viewer.php` (03:52:29), which returned a 302 redirect to login. They then authenticated on `/index.php` (two failed POSTs, success on the third at 03:54:09, redirect to `dashboard.php`) — a pattern consistent with a SQL-injection auth bypass — before returning to `config_viewer.php`.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | ip-10-1-15-67 |
| Timestamp | 2026-02-06 03:52:29 UTC |
| Request | GET `/config_viewer.php` → 302 (340 B) |
| Discovery | listed in `/robots.txt` (read 8 s earlier) |
| Auth bypass | POST `/index.php` ×3 → 302 → GET `/dashboard.php` (03:54:09) |

### 💡 Why it matters
`config_viewer.php` is the pivot for the entire intrusion. It was advertised in `robots.txt`, protected by login, and — once authenticated — exposed an unscoped `file` parameter.

### 🔧 KQL Query Used
```kql
MeridianAccess_CL
| where isnotempty(EventTime_t)
| where ClientIp_s == "10.1.134.57"
| where EventTime_t < datetime(2026-02-06 03:55:05)
| where UserAgent_s !has "Nmap"
| project EventTime_t, UserAgent_s, HttpMethod_s, RequestUri_s, StatusCode_s, ResponseSize_s
| order by EventTime_t asc
```

### 🖼️ Screenshot
<Insert screenshot>

### 🛠️ Detection Recommendation

**Hunting Tip:**
Correlate `robots.txt` reads with immediate follow-up requests to the disallowed paths — attackers use `robots.txt` as a target list. Alert on repeated failed POSTs to a login endpoint followed by a 302 success with no volume, which suggests injection rather than brute force.

</details>

<details>
<summary id="-flag-2-2">🚩 <strong>2.2 What They Pulled</strong></summary>

### 🎯 Objective
Determine what the attacker read through the unscoped file parameter.

### 📌 Finding
**Answer: `/etc/passwd`, then `database.conf`.** Two successful reads (HTTP 200), in order. The first used directory traversal (`../../../etc/passwd`) to escape the web root and enumerate local accounts; the second read the application's own database config directly (no traversal needed).

### 🔍 Evidence

| Field | Value |
|------|-------|
| Read 1 | 04:07:59 — `config_viewer.php?file=../../../etc/passwd` → 200 (3,077 B) |
| Read 2 | 04:08:34 — `config_viewer.php?file=database.conf` → 200 (1,231 B) |
| Source | 10.1.134.57 (curl/8.18.0) |

### 💡 Why it matters
`/etc/passwd` confirmed `svc_backup` existed with a login shell; `database.conf` held reusable database credentials. `database.conf` was read at 04:08:34 — 57 seconds before the `svc_backup` SSH login (04:09:31). The exact credential is not logged (an intentional evidentiary gap); the timing link is strong but the password itself is unconfirmed.

### 🔧 KQL Query Used
```kql
MeridianAccess_CL
| where isnotempty(EventTime_t)
| where RequestUri_s contains "config_viewer"
| where EventTime_t > datetime(2026-02-06 03:54:09)
| where StatusCode_s == "200"
| project EventTime_t, ClientIp_s, UserAgent_s, RequestUri_s, StatusCode_s, ResponseSize_s
| order by EventTime_t asc
```

### 🖼️ Screenshot
<Insert screenshot>

### 🛠️ Detection Recommendation

**Hunting Tip:**
Alert on `file=`/`path=`/`page=` parameters containing `../` sequences (URL-decoded) that return HTTP 200. A 200 (vs 302/403) on a file-parameter endpoint is a successful traversal.

</details>

---

### 🧩 Section 3 — Borrowed Access

<details>
<summary id="-flag-3-1">🚩 <strong>3.1 Borrowed Access</strong></summary>

### 🎯 Objective
Identify the existing account the attacker logged in as over SSH shortly after the config was read.

### 📌 Finding
**Answer: `svc_backup`** — an existing service account, not one the attacker created. Password authentication from 10.1.134.57 succeeded at 04:09:31, 57 seconds after `database.conf` was read.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | ip-10-1-15-67 |
| Timestamp | 2026-02-06 04:09:31 UTC |
| Message | `Accepted password for svc_backup from 10.1.134.57 port 39206 ssh2` |
| Auth type | password (credential reuse, not key) |
| UID | 1001 |

### 💡 Why it matters
Credential reuse from a config file turned a web-app flaw into interactive host access. `svc_backup` returns at 04:47:44 and 04:48:28 for the working sessions that follow.

### 🔧 KQL Query Used
```kql
MeridianAuth_CL
| where isnotempty(EventTime_t)
| where SourceIP == "10.1.134.57"
| project EventTime_t, ProcessName_s, TargetUser_s, SourcePort_s, RawMessage_s
| order by EventTime_t asc
```

### 🖼️ Screenshot
<Insert screenshot>

### 🛠️ Detection Recommendation

**Hunting Tip:**
Correlate successful SSH logins with recent web-app file reads from the same source IP within a short window. A service account logging in interactively over SSH from an external address is inherently suspicious.

</details>

<details>
<summary id="-flag-3-2">🚩 <strong>3.2 The Road Not Taken</strong></summary>

### 🎯 Objective
Identify the two privilege-escalation methods the attacker tried and failed before the SUID shell.

### 📌 Finding
**Answer:** (1) **`sudo -l` as svc_backup** (04:15:07) — denied; the account is not in sudoers (`command not allowed`). (2) **Reused svc_backup password for root over SSH** (04:44–04:46) — failed; the password did not match root. Three attempts came from the host itself (10.1.15.67, port 36868) and three from the attacker IP (10.1.134.57, port 50108).

### 🔍 Evidence

| Field | Value |
|------|-------|
| Method 1 | 04:15:07 — `sudo: svc_backup : command not allowed ; COMMAND=list` |
| Method 2a | 04:44:25–59 — root SSH from 10.1.15.67:36868, 3× failed |
| Method 2b | 04:45:39–04:46:52 — root SSH from 10.1.134.57:50108, 3× failed |

### 💡 Why it matters
These failures show where the host held. Notably, root's password *worked* at 02:48:41 but *failed* by 04:44 — no logged event explains the change (a gap). The root-SSH attempts also occurred **after** the SUID shell already granted root (04:40:15), so they were an attempt at a cleaner interactive root session, not a first escalation.

### 🔧 KQL Query Used
```kql
MeridianAuth_CL
| where isnotempty(EventTime_t)
| where EventTime_t between (datetime(2026-02-06 04:09:00) .. datetime(2026-02-06 04:50:00))
| project EventTime_t, ProcessName_s, TargetUser_s, SourceIP, RawMessage_s
| order by EventTime_t asc
```

### 🖼️ Screenshot
<Insert screenshot>

### 🛠️ Detection Recommendation

**Hunting Tip:**
Alert on `sudo ... command not allowed` and on `Failed password for root` clusters, especially root SSH attempts sourced from the host's own IP (indicating an already-present local session attempting to pivot).

</details>

---

### 🧩 Section 4 — The Planted Root Shell

<details>
<summary id="-flag-4-1">🚩 <strong>4.1 The Planted Root Shell</strong></summary>

### 🎯 Objective
Identify the binary that gave the attacker root, and the flag it was run with.

### 📌 Finding
**Answer: `/tmp/rootbash -p`.** A SUID-root copy of bash, executed at 04:40:15 by svc_backup. The `-p` flag preserves the effective UID so the shell runs as root; the audit record shows real UID 1001 (svc_backup) with effective UID 0.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | ip-10-1-15-67 |
| Timestamp | 2026-02-06 04:40:15 UTC |
| Process | rootbash |
| Executable | `/tmp/rootbash` |
| Command Line | `/tmp/rootbash -p` |
| auid / euid | 1001 / 0 |
| Records | CWD, EXECVE, PATH, PROCTITLE, SYSCALL |

### 💡 Why it matters
This is the successful privilege escalation, bypassing the failed sudo/root-password routes. **Staging is unexplained** — no `cp`/`chmod` is logged. Because the 03:08 sweep cleaned `/tmp` and the host rebooted at 03:23 (Ubuntu clears `/tmp` on boot), `rootbash` must have been created after 03:23, and creating a SUID-root binary requires root that svc_backup did not have. How the first backdoor was staged is an intentional gap.

### 🔧 KQL Query Used
```kql
MeridianAudit_CL
| where isnotempty(EventTime_t)
| where comm_s == "rootbash" or exe_s has "rootbash" or Argv_s has "rootbash"
| project EventTime_t, Types_s, comm_s, exe_s, auid_s, euid_s, Argv_s
| order by EventTime_t asc
```

### 🖼️ Screenshot
<Insert screenshot>

### 🛠️ Detection Recommendation

**Hunting Tip:**
Alert on any process where `auid != euid` and `euid == 0`, especially executing from `/tmp`. A bash process named `rootbash` running with `-p` is a textbook SUID abuse indicator.

</details>

---

### 🧩 Section 5 — Persistence

<details>
<summary id="-flag-5-1">🚩 <strong>5.1 The Second Foothold</strong></summary>

### 🎯 Objective
Identify the stealthier persistence the attacker planted after the noisy `/tmp` shell.

### 📌 Finding
**Answer: `/opt/meridian/scripts/health_check`.** Same SUID technique, far more convincing location — inside the application's own scripts directory, named like a routine monitor. The process snapshot shows it running with the tell-tale UID set `1001/0/0/0` (real svc_backup, effective/saved/fs root), orphaned (PPID 1), started ~04:51 from the attacker's pts/0 session.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | ip-10-1-15-67 |
| Process | health_check (PID 267155) |
| Executable | `/opt/meridian/scripts/health_check` |
| PPID | 1 (orphaned) |
| UID set | 1001 / 0 / 0 / 0 (real / eff / saved / fs) |
| Footprint | 725 MB virtual, state `Sl` (compiled, multi-threaded — likely Go C2) |
| Child procs | bash shells spawned 05:14, 05:19 |

### 💡 Why it matters
Unlike `rootbash`, this binary is sized and structured like a compiled implant, not a bash copy, and it actively spawns shells — behavior consistent with a C2 beacon. Its location keeps it out of any temp-directory cleanup.

### 🔧 KQL Query Used
```kql
MeridianSnapshot_CL
| mv-expand Line = split(ProcessTreeSnapshot_s, "\n")
| extend Line = tostring(Line)
| where Line has_any ("health_check", "svc_bac", "defunct")
| project Line
```

### 🖼️ Screenshot
<Insert screenshot>

### 🛠️ Detection Recommendation

**Hunting Tip:**
Baseline the contents of application script directories and alert on new executables, especially SUID binaries or processes with `auid != euid`. A "monitoring" helper with a 725 MB virtual footprint spawning shells is not a monitor.

</details>

<details>
<summary id="-flag-5-2">🚩 <strong>5.2 Why It Survived</strong></summary>

### 🎯 Objective
Explain why the sweep removed `/tmp/rootbash` but left `health_check` running despite flagging it.

### 📌 Finding
**Answer: wrong location for the cleanup rules.** The sweep only remediates temp directories, SSH keys, and crontabs. A file in the app's `scripts/` directory falls outside that scope — it is compared against a baseline and *flagged* (`Non-baseline file in scripts/: health_check`) but never removed, and no sweep action kills processes outside `/tmp`.

### 🔍 Evidence

| Field | Value |
|------|-------|
| 05:05:06 | `Removed SUID: /tmp/rootbash` (in-scope: temp dir) |
| 05:05:06 | `Non-baseline file in scripts/: health_check` (detected only) |
| Remediation scope | temp dirs, SSH keys, crontabs |
| health_check status | still running as root after the sweep |

### 💡 Why it matters
This is the central "detection ≠ remediation" gap. The stack's remediation logic is path-scoped; the attacker chose a location covered by baseline *monitoring* but not by *remediation*.

### 🔧 KQL Query Used
```kql
MeridianDefender_CL
| where isnotempty(EventTime_t)
| where EventCategory_s startswith "SWEEP"
| summarize Count=count(), First=min(EventTime_t), Last=max(EventTime_t) by RawMessage_s
| order by First asc
```

### 🖼️ Screenshot
<Insert screenshot>

### 🛠️ Detection Recommendation

**Hunting Tip:**
Audit automated remediation tooling for scope gaps: every *detection* category should map to a *remediation* action or an explicit alert-to-human. Baseline-drift detections that produce no remediation must page a responder.

</details>

---

### 🧩 Section 6 — Calling Home

<details>
<summary id="-flag-6-1">🚩 <strong>6.1 Calling Home</strong></summary>

### 🎯 Objective
Identify the C2 destination the backdoor kept reaching for, and whether blocking it neutralised the threat.

### 📌 Finding
**Answer: `10.1.134.57:43212`, not neutralised.** The defence stack logged `Blocked exfil to 10.1.134.57:43212` 73 times between 04:48:28 and 05:02:17. The block stopped packets at the network layer but never killed the process; `health_check` remained resident as root and continued spawning shells afterward.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Destination | 10.1.134.57:43212 |
| Blocks | 73 × `Blocked exfil ... from 10.1.15.67` |
| Window | 04:48:28 → 05:02:17 |
| Process status | PID 267155 still running as root post-block |

### 💡 Why it matters
Port 43212 matches the source port of the `svc_backup` SSH session opened at 04:48:28, and the 73 blocks equal the 73 attacker-IP rows in Syslog over the same window — so some "exfil" blocks are the stack classifying SSH return traffic. Either way, the outbound route was cut while the implant stayed alive.

### 🔧 KQL Query Used
```kql
MeridianDefender_CL
| where isnotempty(EventTime_t)
| where EventCategory_s startswith "NETWORK"
| summarize Count=count(), First=min(EventTime_t), Last=max(EventTime_t) by RawMessage_s, DestIp_s, DestPort_s
| order by First asc
```

### 🖼️ Screenshot
<Insert screenshot>

### 🛠️ Detection Recommendation

**Hunting Tip:**
Treat repeated outbound blocks to one destination as an active-implant indicator, not a resolved event. Pair network-block alerts with a process-level lookup to identify and terminate the source.

</details>

<details>
<summary id="-flag-6-2">🚩 <strong>6.2 What the Block Proves</strong></summary>

### 🎯 Objective
State what the 73 blocks prove about the threat — and what they do not.

### 📌 Finding
**Answer: proves the outbound connection was blocked at the network layer; does not prove the process was killed** (`health_check` was still running). Blocking and process termination are distinct containment actions with different outcomes.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Proven | 73 outbound attempts to 10.1.134.57:43212 were dropped; the network control worked |
| Not proven | that the backdoor was contained — PID 267155 never terminated, still euid 0, spawned shells 05:14 & 05:19 |
| Not proven | that nothing exfiltrated pre-04:48:28 or via other ports/the SSH session |

### 💡 Why it matters
A firewall block acts on packets; it leaves a root-level process fully intact and able to reconnect once the rule lapses, the host reboots, or the implant switches destinations.

### 🔧 KQL Query Used
```kql
MeridianSnapshot_CL
| mv-expand Line = split(ProcessTreeSnapshot_s, "\n")
| extend Line = tostring(Line)
| where Line has "health_check"
| project Line
```

### 🖼️ Screenshot
<Insert screenshot>

### 🛠️ Detection Recommendation

**Hunting Tip:**
In containment playbooks, never mark a C2 finding "resolved" on a network block alone. Require confirmed process termination and binary removal.

</details>

---

### 🧩 Section 7 — Collection

<details>
<summary id="-flag-7-1">🚩 <strong>7.1 What Left the Database</strong></summary>

### 🎯 Objective
Identify the dataset that would matter most if exported from this healthcare portal's backend.

### 📌 Finding
**Answer: patient records (PHI).** The stack's only DB flag reads `Full patient table query`. On a healthcare portal, patient identities, demographics, and medical data are the dataset with real breach impact (HIPAA-class exposure).

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | ip-10-1-15-67 |
| Flag | `Full patient table query` (MeridianDefender_CL, DB) |
| Timestamp | 2026-02-06 02:58:26 UTC |

### 💡 Why it matters
Patient data is the crown-jewel asset here. **Timing caveat:** the flag at 02:58:26 falls in the pre-reboot provisioning window (before the 03:23 boot and long before the real intrusion). It is most consistent with bootstrap seeding/verification of the patient table, not the attacker's export. The dataset *at risk* is patient records; the 02:58 event should not be presented as the confirmed exfiltration. Exact export queries are an intentional gap.

### 🔧 KQL Query Used
```kql
MeridianDefender_CL
| where isnotempty(EventTime_t)
| where EventCategory_s startswith "DB"
| project EventTime_t, EventCategory_s, RawMessage_s
| order by EventTime_t asc
```

### 🖼️ Screenshot
<Insert screenshot>

### 🛠️ Detection Recommendation

**Hunting Tip:**
Alert on full-table reads of sensitive tables (`SELECT *`, `mysqldump`, `INTO OUTFILE` against patient data). Correlate DB flags against confirmed attacker session windows to separate bootstrap noise from real exfiltration.

</details>

<details>
<summary id="-flag-7-2">🚩 <strong>7.2 The Tampered File</strong></summary>

### 🎯 Objective
Identify the config file the final sweep reverted beyond its usual SSH-key/crontab routine.

### 📌 Finding
**Answer: `backup.conf`.** In the final sweep cycle the log line `backup.conf tampered -- reverting` appears (05:05:02), distinct from the routine `SSH keys reverted` / `Crontabs reverted` entries.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | ip-10-1-15-67 |
| Timestamp | 2026-02-06 05:05:02 UTC |
| Message | `backup.conf tampered -- reverting` |
| Context | final IR sweep (05:05:01–05:05:06) |

### 💡 Why it matters
`backup.conf` fits the `svc_backup` account the attacker used — a backup config is a natural target for persistence (injecting a command/script path a root-run backup job would execute). What was changed, and when, is not logged (a gap); only the revert is recorded.

### 🔧 KQL Query Used
```kql
MeridianDefender_CL
| where isnotempty(EventTime_t)
| where EventTime_t >= datetime(2026-02-06 05:00:00)
| where EventCategory_s !startswith "WEB"
| project EventTime_t, EventCategory_s, RawMessage_s
| order by EventTime_t asc
```

### 🖼️ Screenshot
<Insert screenshot>

### 🛠️ Detection Recommendation

**Hunting Tip:**
Read every line of a remediation cycle, not just the summary. File-integrity monitoring on service config files (backup, cron-invoked scripts) catches tampering that key/crontab reverts miss.

</details>

---

### 🧩 Section 8 — Defence Evasion & Detection Gaps

<details>
<summary id="-flag-8-1">🚩 <strong>8.1 Signal or Setup Noise</strong></summary>

### 🎯 Objective
Determine whether the early burst of detections (SSH-key/crontab/new-service, auto-reverted) was intrusion or something else.

### 📌 Finding
**Answer: false positive.** The 02:53:31 burst (4× SSH-key, 3× crontab, 2× new-systemd-service, all reverted within a second) has no correlating attacker activity. The confirmed attacker source (10.1.134.57) has no session between 02:48:42 and 03:47:32, and the burst rows carry a blank/localhost SourceIP.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Burst | 02:53:31 — 9 detections (SSH keys, crontabs, new systemd services), all reverting |
| Attacker correlation | none — no 10.1.134.57 activity 02:48:42–03:47:32 |
| Supporting noise | `Login 'svc_backup' from 127.0.0.1` (02:56:33, localhost, pre-credential-theft) |
| First sweep | 03:08 — removed `sysmon.service`, reverted keys/crontabs, cleaned temp |

### 💡 Why it matters
A detection log is not proof of attack. This burst is the defence stack reacting to its own installation/bootstrap. Misreading it as intrusion would invent a phantom early-persistence phase.

### 🔧 KQL Query Used
```kql
MeridianDefender_CL
| where isnotempty(EventTime_t)
| where EventTime_t < datetime(2026-02-06 03:47:32)
| project EventTime_t, EventCategory_s, SourceIP, RawMessage_s
| order by EventTime_t asc
```

### 🖼️ Screenshot
<Insert screenshot>

### 🛠️ Detection Recommendation

**Hunting Tip:**
Always correlation-check detection bursts against confirmed attacker source IPs and session windows before attributing them. Batch changes reverted within one second are automation, not a human operator.

</details>

<details>
<summary id="-flag-8-2">🚩 <strong>8.2 Collateral Damage</strong></summary>

### 🎯 Objective
Identify legitimate tooling the first sweep removed as "collateral damage."

### 📌 Finding
**Answer: `sysmon.service` — Sysmon for Linux telemetry lost** (process-creation, network-connection, and file-creation logging). The first IR sweep removed it at 03:08:20, 39 minutes before the intrusion, during the provisioning window.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | ip-10-1-15-67 |
| Timestamp | 2026-02-06 03:08:20 UTC |
| Message | `Removed service: sysmon.service` |
| Attacker correlation | none (pre-intrusion, provisioning window) |

### 💡 Why it matters
The sweep's baseline-revert logic could not distinguish attacker-planted from legitimate-but-post-baseline tooling, and blinded the host. This directly explains the hunt's biggest gaps — how `rootbash` and `health_check` were staged, and which process owned the outbound connections — all of which Sysmon file/process/network events would have captured.

### 🔧 KQL Query Used
```kql
MeridianDefender_CL
| where isnotempty(EventTime_t)
| where RawMessage_s has_any ("service", "systemd")
| project EventTime_t, EventCategory_s, RawMessage_s
| order by EventTime_t asc
```

### 🖼️ Screenshot
<Insert screenshot>

### 🛠️ Detection Recommendation

**Hunting Tip:**
Allowlist approved monitoring agents in baseline-revert tooling, or add them to the baseline before enabling auto-remediation. Alert when a defensive service is stopped/removed rather than silently reverting it.

</details>

---

### 🧩 Section 9 — Response

<details>
<summary id="-flag-9-1">🚩 <strong>9.1 Capturing the Evidence</strong></summary>

### 🎯 Objective
Identify the volatile-state capture the returning admin performed, and where the output landed.

### 📌 Finding
**Answer: avml → `/tmp/evidence/memory.lime`.** The responder (`ubuntu`, uid 1000, key-auth from 10.0.2.139, elevated via `sudo /bin/bash`) ran Microsoft AVML twice — 05:27:48 and 05:28:24 — capturing a full memory image in LiME format while the backdoor was still running.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Tool | avml (`/tmp/avml`) |
| Output | `/tmp/evidence/memory.lime` |
| Run 1 | 05:27:48 (`/tmp/avml /tmp/evidence/memory.lime`) |
| Run 2 | 05:28:24 (same path — second run overwrote the first) |
| Operator | uid 1000 (ubuntu), euid 0 |

### 💡 Why it matters
Capturing memory before disturbing the live implant is correct forensic order — the backdoor's in-memory config and C2 state are preserved. Caveat: both tool and output live in `/tmp`, which is inside the sweep's cleanup path and cleared on reboot; the image should be moved to external storage and hashed immediately.

### 🔧 KQL Query Used
```kql
MeridianAudit_CL
| where isnotempty(EventTime_t)
| where comm_s == "avml" or exe_s has "avml" or Argv_s has "avml"
| project EventTime_t, comm_s, exe_s, auid_s, euid_s, Argv_s
| order by EventTime_t asc
```

### 🖼️ Screenshot
<Insert screenshot>

### 🛠️ Detection Recommendation

**Hunting Tip:**
Distinguish responder activity from intrusion by login UID and source IP — a root binary in `/tmp` (AVML) is IR here, identified by uid 1000 from 10.0.2.139, not the attacker. Store captures outside swept paths and pause automated sweeps during live response.

</details>

<details>
<summary id="-flag-9-2">🚩 <strong>9.2 What's Still Live</strong></summary>

### 🎯 Objective
Identify the one concrete manual action still required before the incident can be called contained.

### 📌 Finding
**Answer: manually kill the `health_check` backdoor (PID 267155) and remove the SUID binary `/opt/meridian/scripts/health_check`.** It is the only attacker foothold still active — detected, memory-captured, but never terminated.

### 🔍 Evidence

| Artefact | Automated action | Status |
|---|---|---|
| `/tmp/rootbash` process (PID 265440) | killed 05:05:01 | ✅ fixed |
| `/tmp/rootbash` SUID bit | removed 05:05:06 | ✅ fixed |
| SSH keys / crontabs | reverted 05:05:01 | ✅ fixed |
| `backup.conf` | reverted 05:05:02 | ✅ fixed |
| Temp dirs | cleaned 05:05:06 | ✅ fixed |
| Outbound to 10.1.134.57:43212 | blocked ×73 | ⚠️ traffic stopped, source alive |
| **`/opt/meridian/scripts/health_check`** | **logged only** | ❌ **still running as root** |

### 💡 Why it matters
PID 267155 runs euid 0, detached (PPID 1), and spawned shells at 05:14 and 05:19 — after the sweep. No Defender or responder action ever terminated it. The network block is not containment while the process lives.

### 🔧 Remediation Order
1. Copy `/tmp/evidence/memory.lime` off-host and hash it (it sits in a swept path).
2. `kill -9 267155`.
3. Preserve, then remove/strip the binary: `chmod u-s /opt/meridian/scripts/health_check`, move to evidence storage.
4. Close the still-open `svc_backup` pts/0 session (from 04:09) and reset the `svc_backup` credential taken via `database.conf`.

### 🔧 KQL Query Used
```kql
MeridianAudit_CL
| where isnotempty(EventTime_t)
| where EventTime_t >= datetime(2026-02-06 04:51:00)
| where Argv_s has_any ("health_check", "267155") or comm_s in~ ("kill", "pkill", "rm", "chmod", "mv")
| project EventTime_t, comm_s, exe_s, auid_s, euid_s, Argv_s
| order by EventTime_t asc
```

### 🖼️ Screenshot
<Insert screenshot>

### 🛠️ Detection Recommendation

**Hunting Tip:**
Reconcile every *detected* artefact against a *remediated* artefact at incident close. Any detection without a matching remediation is an open containment gap.

</details>

---

## 🚨 Detection Gaps & Recommendations

### Observed Gaps
- **Remediation scope is path-bound.** The sweep only acts on `/tmp`, SSH keys, and crontabs. `/opt/meridian/scripts/health_check` was detected but never removed or killed — the live backdoor at end of window.
- **Defensive tooling removed by baseline-revert.** `sysmon.service` was stripped at 03:08:20, erasing process/file/network telemetry for the entire intrusion and creating the staging gaps below.
- **Staging of both SUID backdoors is unrecorded.** No `cp`/`chmod` for `/tmp/rootbash` or `/opt/meridian/scripts/health_check` exists in any table (consistent with the Sysmon removal and the intentional "how the first backdoor was staged" gap).
- **Bootstrap noise vs. real signal.** The 02:53 detection burst, 02:56 localhost `svc_backup` login, and 02:58 `Full patient table query` are provisioning artefacts, not attacker activity, yet sit in the same log stream.
- **Network block misclassification.** Some of the 73 "exfil" blocks to 10.1.134.57:43212 are SSH session return traffic (matching the svc_backup source port), not implant beacons.
- **Unexplained root-password change.** Root password worked at 02:48:41, failed by 04:44 — no logged cause.
- **Evidence stored in a swept path.** `/tmp/evidence/memory.lime` is exposed to sweep cleanup and reboot clearing.

### Recommendations
- Map every detection category in the defence stack to a remediation action or an explicit human-alert; page a responder on any baseline-drift detection that produces no remediation.
- Allowlist approved security agents (Sysmon) in the baseline before enabling auto-revert; alert on removal of defensive services.
- Enable and protect process-, file-, and network-creation logging (Sysmon for Linux or auditd EXECVE with full argv) so staging events are captured.
- Pair network-block alerts with a process-level lookup and mandatory termination; never close a C2 finding on a block alone.
- During live response, pause automated sweeps and write captures to external/network storage, hashed on creation.
- Rotate `svc_backup` credentials, remove the account's reusable password from `database.conf`, and scope `config_viewer.php`'s `file` parameter to an allowlist.

---

## 🧾 Final Assessment

A methodical external attacker chained a web-app path-traversal flaw and credential reuse into interactive SSH access, then escalated to root via a pre-staged SUID shell and established a stealthy, compiled backdoor masquerading as an application health-check. Sophistication was moderate but disciplined: the attacker deliberately chose a persistence location outside the defence stack's remediation scope, which is why it survived. The automated defence stack performed real work — killing the `/tmp` shell, reverting keys/crontabs/`backup.conf`, blocking outbound C2 — but its path-bound remediation logic and its self-inflicted removal of Sysmon left both a live root backdoor and major evidentiary gaps. **The host is not contained.** Until `health_check` (PID 267155) is manually terminated and removed and `svc_backup` is rotated, the attacker retains root-level persistence. Given the patient-data estate, this is a high-severity incident with regulatory exposure.

---

## 📎 Analyst Notes

- All queries filter and order by `EventTime_t`; `isnotempty(EventTime_t)` excludes failed-ingestion rows. `MeridianSnapshot_CL` and `MeridianNetwork_CL` (no `EventTime_t`) were analyzed on structure.
- Responder activity (uid 1000 `ubuntu` from 10.0.2.139; AVML; 05:22–05:28) was separated from intrusion activity throughout and is not attributed to the attacker.
- Intentional evidentiary gaps (exact credentials, exact export queries, backdoor staging) are flagged as unproven rather than filled with assumption.
- Report structured for interview and portfolio review across the 9 hunt sections; evidence reproducible via advanced hunting; techniques mapped to MITRE ATT&CK.
