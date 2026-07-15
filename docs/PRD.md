# PRD: EventIQ

Requirements for v1, written 2026-07-14. Timebox: **2 days**, single builder.
That constraint drives every scope decision below, especially section 5.

---

## 1. Problem statement (three sentences, non-technical)

A security team has a log file with a million lines of network, login, DNS and
system activity, and somewhere inside it are real attacks hidden among normal
traffic. Reading it by hand is impossible, and the obvious shortcut of trusting
the file's own labels proves nothing. EventIQ reads the raw activity, finds
the attacks on its own, ranks them by how dangerous they are, and produces a
report and a dashboard an analyst can act on in minutes, along with a score
showing how accurate its detections actually were.

---

## 2. Users and their jobs

| User | Their job | What EventIQ gives them |
|---|---|---|
| **Tier-1 SOC analyst** (fictional end user) | Triage fast: what do I look at first, and why | Findings ranked by severity and entity risk, each with the evidence that fired it, in a scannable dashboard |
| **Syed Jawad** (team lead, real reviewer) | Judge whether Ismi thinks like a detection engineer | Sourced thresholds, MITRE mappings, a measured precision/recall table, an honest limitations section, Wazuh + Sigma exports his team could deploy |
| **Ismi** (builder) | Ship something defensible line by line | Clean tested code, config-driven rules, a README that tells the whole story |

---

## 3. Functional requirements

Each is one sentence and testable. Priority: **M** must-have (Day 1 core),
**S** should-have (Day 2), **C** could-have (only if time remains).

**Ingest and parse**
- **FR-1 (M):** Parse the provided CSV by streaming, holding memory roughly
  constant regardless of file size (target under 200 MB peak on the 1M-row file).
- **FR-2 (M):** Map raw columns onto Wazuh-native field names (`srcip`, `dstip`,
  `srcport`, `dstport`, `srcuser`, `protocol`, `action`, `status`) during parse.
- **FR-3 (M):** Count and report malformed rows rather than crashing on them; a
  `--strict` flag turns malformed rows into a non-zero exit.

**Detection (reads raw fields only, never `event_type` or `severity`)**
- **FR-4 (M):** Detect the distributed port scan by pivoting on destination and
  counting distinct source IPs and subnets converging on it, with negative-
  response (blocked, zero-bytes-back) as a supporting feature.
- **FR-5 (M):** Detect the distributed SSH brute force / password spray by
  destination and username, counting distinct failing sources and separating it
  from ordinary background failed logins.
- **FR-6 (M):** Detect DNS tunneling by Shannon entropy and label length of the
  subdomain, combined with per-domain query volume, not entropy alone.
- **FR-7 (M):** Detect connections to known-suspicious domains via a configurable
  indicator list and TLD heuristics.
- **FR-8 (M):** Detect malicious PowerShell by matching encoded-command,
  download-cradle, hidden-window and execution-policy-bypass patterns in the
  command field.
- **FR-9 (M):** Detect command-and-control indicators by destination port
  (4444 and a configurable IOC port list).

**Correlate and score**
- **FR-10 (S):** Assign each finding a MITRE ATT&CK technique ID and a Wazuh rule
  level (0-15) with a documented justification for the level chosen.
- **FR-11 (S):** Accumulate a per-entity (IP, user) risk score so converging
  detections on one entity rise to the top, mirroring risk-based alerting.
- **FR-12 (S):** Group related alerts sharing an entity and time window into
  incidents.

**Report and validate**
- **FR-13 (M):** Emit a machine-readable JSON report whose alert records mirror
  the Wazuh alert envelope (`rule.id`, `rule.level`, `rule.mitre`, `data.*`).
- **FR-14 (M):** Emit a JSON Lines alert stream ingestible by Wazuh's built-in
  JSON decoder.
- **FR-15 (M):** Score detections against the held-out `event_type` labels and
  report precision, recall and F1 per rule.
- **FR-16 (S):** Render a self-contained HTML dashboard (single file, no external
  requests) with the KPI strip, severity-over-time chart, alert table and
  per-incident drill-down.
- **FR-17 (S):** Export detected patterns as Wazuh rule XML (IDs 100000-120000)
  and as Sigma YAML.

**Interface**
- **FR-18 (M):** Provide a command-line interface with subcommands `analyze` and
  `validate`, plus flags for output paths, config file, time window, minimum
  severity, and engine choice.
- **FR-19 (M):** Exit 0 on a clean run, 1 when alerts at or above the minimum
  severity are found, 2 on input or config error, so the tool composes into a
  pipeline.

**Could-have (only if the schedule holds)**
- **FR-20 (C):** Serve the dashboard from the same JSON via a small local HTTP
  server (the "live app" stretch).
- **FR-21 (C):** An optional, off-by-default AI layer that writes an incident
  narrative and suggested triage steps from aggregated findings, never raw logs.

---

## 4. Non-functional requirements

- **NFR-1 Performance.** Analyze the 1M-row / 132 MB file in under 90 seconds on
  a normal laptop, peak memory under 200 MB. Memory must be a function of
  detection window size and active entity count, not input size.
- **NFR-2 Portability.** Runs on Python 3.11+ with a tiny dependency set
  (`jinja2`, `pyyaml`; dev-only `pytest`, `hypothesis`, `ruff`, `mypy`). No
  pandas. Optional `polars` behind a flag.
- **NFR-3 Reproducibility.** Same input plus same config yields byte-identical
  JSON output (stable ordering, no wall-clock in the payload except a stamped
  `generated_at`).
- **NFR-4 Tool security.** The tool is itself a security artifact: no `eval`, no
  shelling out on log content, HTML output autoescaped so a crafted domain or
  command in the log cannot inject script into the dashboard, no secrets in the
  repo, AI layer off by default and sending only aggregates.
- **NFR-5 Configurability.** Every threshold, IOC list and toggle lives in a YAML
  config with safe defaults baked into code; unknown config keys are rejected
  rather than silently ignored. No attack-specific constant (a target IP, a
  subnet) is hardcoded in detection logic.
- **NFR-6 Legibility.** Every alert states, in plain fields, why it fired (the
  evidence: counts, thresholds, sample source rows by line number).

---

## 5. Out of scope for v1 (aggressive, on purpose)

Two days means saying no to almost everything. These are deliberately excluded:

- **Volume-based exfiltration detection** and **off-hours / beaconing
  detection.** Not descoped for time: the data cannot support them (SPEC section
  4). They would be pure false positives. The report explains why instead.
- **Live streaming / real-time ingestion.** Batch analysis of a file is the job.
- **Multi-format parsing** (syslog, Windows Event Log, Zeek, PCAP). One CSV
  schema for v1.
- **A database or persistence layer.** Input is a file, output is a file.
- **User accounts, authentication, multi-tenancy** on any served dashboard.
- **Machine-learning anomaly detection.** Unexplainable alerts are worthless to a
  SOC and would add a heavy dependency. Deterministic, explainable rules only.
- **Deploying the exported Wazuh rules into a live manager.** We produce the XML;
  deploying it is the team's call.
- **The AI layer and the live web app are could-haves, not commitments.** If Day
  2 runs short they are cut without touching the graded core.

---

## 6. Success criteria (what makes the reviewer say "solid")

1. EventIQ finds all five attack campaigns in the file and proves it with a
   precision/recall/F1 table against held-out ground truth, not by assertion.
2. It separates the real distributed brute force from the 28,889 background
   failed logins, and the number shows it (precision well above a naive
   "any failed login" baseline).
3. It names the two detections the data cannot support and shows the numbers
   that make them traps.
4. Every threshold traces to a primary source; every finding carries a MITRE ID
   and a justified Wazuh level.
5. It runs on a second CSV of the same schema with no code change, because
   nothing attack-specific is hardcoded.
6. The code passes `pytest`, `ruff`, and `mypy`, and the README tells the whole
   story in under two minutes of skim.

---

## 7. Risks and mitigations (max 6)

| # | Risk | Mitigation |
|---|---|---|
| R-1 | 2-day scope collapses; stretch features eat the core | Walking skeleton first (parse -> one detector -> JSON -> validate end to end on Day 1 morning); stretch features are strictly additive and cuttable |
| R-2 | Detectors overfit to this file's constants (172.16.10.25, 203.0.0.0/16) | All thresholds and IOCs in config; detectors key on structural features (distinct-source convergence), validated to work without the specific constants |
| R-3 | DNS entropy rule false-positives on legitimate high-entropy domains | Combine entropy with length and volume, keep an allowlist, report the FP mode honestly rather than hiding it |
| R-4 | Validation scoring is gamed by matching alerts back to labels loosely | Define the match rule precisely (entity + time-window containment), report both row-level and alert-level precision/recall, and document the choice |
| R-5 | HTML dashboard injects log content unsafely (XSS in a security tool) | Jinja2 autoescape on, embed JSON as a `<script type="application/json">` island with `<`/`>` escaped, no CDN so a strict CSP holds |
| R-6 | An unsourced SIEM claim slips into the docs and the reviewer catches it | Every claim in RESEARCH.md already carries a source URL; the exported rule levels cite the Wazuh classification table |

---

## Status

Requirements are locked. The architecture decisions that follow from them are
in `docs/build-log/COUNCIL.md`.
