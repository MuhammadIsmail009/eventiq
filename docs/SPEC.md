# Specification: EventIQ

The assignment brief, the requirements extracted from it, and the profiling
that grounded every scope decision below. Written 2026-07-14.

---

## 1. The brief, verbatim

> **Python Task: Network Security Log Analysis Tool**
>
> **Objective:**
> Develop a Python-based tool that analyzes network and authentication logs and
> identifies potentially suspicious activity.
> This task is designed to assess your understanding of Python programming,
> Network+ concepts, log analysis, and basic security investigation.
>
> **Scenario:**
> An organization has provided a log file containing network connections,
> authentication attempts, DNS activity, and system events.
> The security team wants a Python tool that can process the provided logs,
> identify unusual activities, and generate a structured summary of the findings.
>
> You are required to design and develop this tool independently.

Provided artifact: `network_security_logs_1_million.csv`.

### Scope added on top of the brief

These are self-imposed, not required by the assessment. They are what turns a
passing submission into a memorable one, and they are also the main scope risk.

- A **dashboard / user interface**, not just console output.
- Room for an optional AI-assisted triage layer, left as future work rather
  than shipped, since it would compete with detection quality for review time.
- Design quality benchmarked against a set of studio websites.
- Research depth against Splunk, CrowdStrike and Wazuh documentation.

---

## 2. Extraction

### Goal

Ship a tool that reads the provided log file, finds the malicious activity
hiding in it, and produces a summary a human analyst can act on. The assessment
is really measuring four things at once: Python engineering, networking
fundamentals, log analysis method, and security investigation reasoning.

The word "independently" in the brief is doing real work. The graders want to
see judgement, not just working code.

### Stakeholders

| Who | What they want | What makes them say "solid" |
|---|---|---|
| **Syed Jawad** (team lead, reviewer) | Evidence Ismi can think like a detection engineer | Sourced claims, honest limitations, measured detection quality, code he could hand to a junior |
| **Ismi** (builder) | A first project that earns trust and teaches him the craft | Something he can defend line by line in a review |
| **A hypothetical tier-1 analyst** (the fictional end user) | To know what to look at first, and why | Ranked findings with evidence attached, not a wall of rows |

### Constraints

- **Time.** An internship project, not a product. Assume a small number of weeks
  and a single builder. Every feature competes with polish on the core.
- **Tooling context.** The team runs **Wazuh**. Vocabulary that matches their
  daily tooling (rule levels, MITRE ATT&CK identifiers, Sigma) will land better
  than an invented taxonomy.
- **Input is a single static CSV file.** Not a live stream, not an API. The tool
  should not pretend otherwise, but it also should not be architecturally unable
  to grow into a stream.
- **Reviewed by a detection engineer.** Unsourced claims about how a SIEM works
  are worse than saying nothing.

### Success criteria (drafted here, refined in the PRD)

1. The tool finds every attack campaign present in the file, and can prove it
   with numbers rather than assertion.
2. It does not cry wolf. False positives are measured and reported, not hidden.
3. Someone else can run it on a different CSV and it still works.
4. The reasoning is legible: for each finding, why it fired and what evidence
   backs it.
5. It states what it cannot do. See the traps in section 4.

---

## 3. What is actually in the log file

Profiled directly from the file, not assumed. This section is the reason the
plan looks the way it does.

```
rows           1,000,000
size           132 MB
span           2026-07-01 00:00:01  ->  2026-08-04 17:19:57  (35 days)
columns        log_id, timestamp, source_ip, destination_ip, source_port,
               destination_port, protocol, service, username, event_type,
               event_status, domain, command, bytes_sent, bytes_received,
               severity
```

Distributions:

```
event_type            NETWORK_CONNECTION 560,694   DNS_QUERY 159,342
                      LOGIN 120,383               FILE_ACCESS 59,581
                      POWERSHELL 40,088           FAILED_LOGIN_BURST 24,923
                      PORT_SCAN 16,842            SUSPICIOUS_DNS 10,176
                      DNS_TUNNELING 5,044         SUSPICIOUS_POWERSHELL 2,927

event_status          SUCCESS 911,199  FAILED 53,812  ALLOWED 18,147  BLOCKED 16,842
protocol              TCP 719,860  UDP 250,112  ICMP 30,028
severity              LOW 594,879  MEDIUM 355,385  HIGH 41,765  CRITICAL 7,971
username              16 distinct
service               23 distinct   (DNS, SMB, SSH, RDP, HTTP, ... )
domain                empty on 825,438 rows
command               empty on 956,985 rows
```

### 3.1 The dataset ships with its own answer key

`event_type` and `severity` are **labels**, not observations. A tool that
filters `event_type == "PORT_SCAN"` and calls that detection has detected
nothing. It has read the answer key.

**Design consequence, and the central decision of this project:**

> The detection engine reads only raw observable fields: timestamp, IPs, ports,
> protocol, service, username, event_status, domain, command, bytes.
> It never reads `event_type` or `severity`.
> Those two columns are held out and used only to score the detectors.

That gives the project something almost no internship submission has: a
**measured precision, recall and F1 per detection rule**, against ground truth.

### 3.2 The attacks are distributed, which breaks the textbook rules

This is the finding that most changes the architecture.

**Port scan.** 16,842 events. But they come from **14,814 distinct source IPs**.

```
rows per scanning source IP:   1 -> 12,938 IPs
                               2 ->  1,733 IPs
                               3 ->    134 IPs
                               4 ->      9 IPs
distinct ports per source IP:  1 -> 13,007 IPs      (i.e. one port, once)
```

Every one of them sits in `203.0.0.0/16`, and every one of them targets the
same host: `172.16.10.25`. All BLOCKED. `bytes_received` is 0 and `bytes_sent`
is 43 to 120 bytes, which is the signature of a connection that was refused.

The classic rule, "alert when one source IP contacts more than 20 distinct ports
in 60 seconds", would fire **zero times** on this data. The scan is horizontally
spread across thousands of throwaway source addresses, which is what a botnet or
a proxy-rotating scanner actually looks like.

The signal is **convergent**, so the detector must be too:

```
       203.0.x.x  (14,814 sources)                  the pivot is the
            \  |  /                                 DESTINATION, plus
             \ | /                                  source-subnet
              \|/                                   aggregation.
        172.16.10.25   <-- one target, 16,842 hits, all blocked, 0 bytes back
```

Benign traffic to `172.16.10.25`: **6 events** in 35 days. So a
destination-pivot detector is nearly noise-free here.

**Brute force.** Same shape. 24,923 events, **15,926 distinct source IPs**, all
in `185.199.0.0/16`, all onto `10.10.20.15:22` (SSH), all FAILED, concentrated
on the usernames `admin` and `administrator`. Benign traffic to that host: 2
events. Max failed attempts from any single IP across the whole 35 days: **43**.

This is a distributed password-spray, not a brute force from one box.

### 3.3 What separates cleanly

- **DNS tunneling.** 5,044 events, every one a unique domain, shaped like
  `7ig2sk1zhcdzsvymj1e9x19od2kwg84upg897c167v8669rmfhip7kv.data-transfer.example`.
  That is a 54-character random label. Meanwhile the entire file contains only
  **10 benign domains** (wazuh.com, github.com, cloudflare.com, and 7 others).
  Shannon entropy plus label length will separate these almost perfectly.
- **Suspicious domains.** 6 static bad domains, on `.click`, `.site`, `.top`
  and `.info`: `powershell-download.site`, `freevpn-access.click`,
  `login-security-check.info`, `cdn-account-verify.top` and two more.
- **Malicious PowerShell.** The file contains exactly **6 distinct command
  strings**. Two are benign (`Get-Process`, `Get-Service`). Four are malicious:
  `-enc BASE64_PAYLOAD`, `-ExecutionPolicy Bypass -EncodedCommand`,
  `(New-Object Net.WebClient).DownloadString(...)`, and
  `-WindowStyle Hidden Invoke-Expression $cmd`.
- **Command and control indicator.** Destination port **4444** appears 19,614
  times, carrying the service label `UNKNOWN`. 4444 is the Metasploit default
  handler port.

### 3.4 The noise floor (this is what makes a precision number mean something)

**28,889 LOGIN rows have `event_status = FAILED` but are NOT labelled
`FAILED_LOGIN_BURST`.** They are background authentication failures scattered
across the environment.

A lazy detector that alerts on "any failed login" gets high recall and awful
precision. Separating the real distributed campaign from this background is the
actual detection problem. It is the reason the precision/recall table will be
interesting rather than a row of 1.00s.

---

## 4. Two traps. Detections that look obvious and are not viable here.

Both of these are on every "network log analysis" tutorial. Both would be pure
false positives on this file. Finding this out cost one profiling pass and it is
worth more than any feature.

### Trap 1: data exfiltration by byte volume

Total bytes (sent + received), by event type:

```
event_type              median        p95         max
DNS_QUERY            3,502,555    5,993,303   6,994,997     <-- a 3.5 MB DNS query
DNS_TUNNELING        3,462,454    6,015,987   6,958,859
FAILED_LOGIN_BURST   3,468,339    5,984,173   6,967,342     <-- 3.5 MB failed SSH login
LOGIN                3,488,224    5,999,571   6,976,326
NETWORK_CONNECTION   3,500,980    6,001,186   6,995,764
POWERSHELL           3,507,526    6,009,403   6,992,919
PORT_SCAN                   80          116         120     <-- the only real signal
```

The byte columns are uniform random noise, identical across benign and malicious
traffic. There is no volume signal to find. A "large outbound transfer" rule
would rank random benign rows as the top exfiltration events.

**Decision: do not ship a volume-based exfiltration detector. Document why.**
The low-byte / zero-response signal (PORT_SCAN, median 80 bytes) IS real and
will be used as a supporting feature for scan detection.

### Trap 2: off-hours activity and C2 beaconing

Hour-of-day distribution, for every event type including the attacks:

```
00:4%  01:4%  02:4%  03:4%  04:4%  05:4%  06:4%  07:4%  08:4%  09:4%  10:4%  11:4% ...
```

Uniform. 1/24 of events in every hour. There is no working day in this data, so
there is no "unusual 3am login". Timestamps are also random rather than
periodic, so there is no beaconing interval to recover.

**Decision: do not ship an off-hours or beaconing detector. Document why.**

### Why this belongs in the report

Naming the two things the data cannot support, with the numbers that prove it,
is a stronger signal to a detection engineer than adding two more rules that
quietly produce garbage. Knowing your own false-positive modes is the job.

---

## 5. Ambiguities in the brief

1. "Structured summary" is undefined. JSON? A console table? A written report?
   A dashboard? The brief allows all of them and specifies none.
2. "Suspicious" and "unusual" are undefined. There is no baseline period given,
   no asset inventory, no allowlist of known-good behaviour.
3. No indication whether the grader will run the tool on a *different* log file
   with the same schema. This changes how much hardcoding is acceptable.
4. Nothing says whether the embedded `event_type` labels are meant to be used or
   held out. Both readings are defensible. The held-out reading is stronger and
   is the one taken here, but the report must state the choice explicitly.

---

## 6. Open questions, ranked by how much the answer changes the architecture

Left open at this stage; resolved later once the rest of the profiling was done.

1. **Will the tool be run against a second, unseen log file with the same
   schema?** If yes, every hardcoded value (`172.16.10.25`, `203.0.0.0/16`,
   the 6 known bad domains) must become a learned or configured value rather
   than a constant. This is the single biggest fork in the design.
2. **Does the deliverable include the dashboard, or is the dashboard a personal
   stretch goal?** A self-contained HTML report and a live web application are
   very different amounts of work and risk. Which one is graded?
3. **Should the output be importable into Wazuh** (as custom rules and decoders
   for the team's real platform), or is it a standalone report? Producing
   Wazuh rule XML alongside the Python findings would speak directly to Syed
   Jawad's world, but it doubles the surface area.
4. **Is an AI/LLM component acceptable to the reviewer, or will it read as a
   gimmick that hides weak detection logic?** Also: is sending log data to an
   external API acceptable at Ebryx, or must it run offline?
5. **What is the actual deadline, in weeks?** The scope decisions below all
   hinge on it and it is currently unknown.
6. **Is the tool expected to handle log formats other than this CSV** (syslog,
   Windows Event Log, Zeek), or is one schema enough for v1?
7. **How much does code quality weigh against feature count** in the grade?
   Tests, typing and documentation versus more detection rules.
8. **Is there an expectation of live/streaming operation**, or is batch analysis
   of a file the whole job?

---

## 7. Status

This document is the ingest pass. The sourced platform research it feeds into
lives in `docs/RESEARCH.md`.
