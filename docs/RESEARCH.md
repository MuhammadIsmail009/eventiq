# RESEARCH: SOC Project 1

Written 2026-07-14. Every SIEM/EDR claim below carries the official source URL
it was verified against. Items that could not be verified are marked
UNVERIFIED and are not stated as fact.

---

## Executive summary (read this, skip the rest if short on time)

1. **Speak Wazuh's field names.** If our parsed columns are named exactly
   `srcip, dstip, srcport, dstport, srcuser, protocol, action, status`, they
   become Wazuh's own static decoder fields and everything downstream (rule
   elements, dashboard pivots, `same_srcip` correlation) works for free.
   Any other name silently becomes a "dynamic field".
2. **Emit JSON Lines, not CSV.** Wazuh has no `csv` log format, but it has a
   built-in `json` decoder. One `<localfile>` stanza and our output is
   ingestible with zero decoder work.
3. **Mirror the real Wazuh alert envelope**: `rule.id` (string), `rule.level`
   (int 0-15), `rule.description`, `rule.groups[]`, `rule.mitre.{id,tactic,
   technique}`, `data.{srcip,...}`, `full_log`, `timestamp` (ISO-8601 Z).
4. **The aggregation key is the whole game.** Vertical scan groups by
   `(src,dst)`; horizontal sweep by `(src,dst_port)`; **distributed scan groups
   by `dst` and counts distinct `src`**. Our data is the distributed case, which
   Wazuh's native `same_srcip` cannot express. That gap is what our tool fills.
5. **Thresholds we adopt, each from a primary source:** vertical scan 15 ports
   / 5 min (Zeek), distributed scan 25 distinct sources on one dest (Snort/Zeek),
   DNS tunneling entropy > 3.0 AND subdomain length > 20 (Splunk URL Toolbox),
   brute force 5-10 consecutive failures (Elastic), spray >= 10 distinct users
   per source (Splunk ESCU). Never entropy alone: cloud/CDN domains false-positive.
6. **Number custom rules 100000-120000** (Wazuh's reserved custom band) and tag
   each with a MITRE technique ID only; let the platform resolve tactic + name.
7. **MITRE renamed tactic TA0005 from "Defense Evasion" to "Stealth".** Wazuh and
   Sigma still emit the old string. Key on technique IDs, never tactic names.
8. **Sigma has no stock SSH brute-force rule.** Brute force is a Sigma
   *Correlation* (`event_count`), not a stock YAML detection. We write it
   ourselves; Wazuh's `0095-sshd_rules.xml` is the reference.
9. **Design direction "Terminal Editorial":** dark charcoal (not pure black),
   one accent, hierarchy from type *weight* not color, monospace for all IPs /
   ports / hashes / commands. Severity encoded on colour AND shape AND label,
   because a colour-only severity scale fails ~8% of male analysts.
10. **claude-mem: skip.** Native memory + a session log cover the need without
    adding a single-maintainer background daemon to a security project.

---

## Section A: SIEM / EDR landscape

### A1. Wazuh (primary platform, deepest section)

**Architecture and data flow.**
Agent -> server (TCP 1514, AES) -> `analysisd` (decode, then rule match) ->
Filebeat -> indexer (TCP 9200, TLS) -> dashboard (server API on TCP 55000).
Decoders "extract relevant information from the logs and map them to appropriate
fields"; `analysisd` "evaluates the decoded logs against rules". Alerts are
written to `/var/ossec/logs/alerts/alerts.json`.
(https://documentation.wazuh.com/current/getting-started/architecture.html,
https://documentation.wazuh.com/current/user-manual/capabilities/log-data-collection/how-it-works.html,
https://documentation.wazuh.com/current/user-manual/manager/alert-management.html)

**Rule XML syntax.** A `<rule>` carries attributes `id` (1-999999), `level`
(0-16), `frequency` (2-9999), `timeframe` (1-99999 seconds), `ignore` (seconds
to suppress after firing), `overwrite`, `noalert`, `maxsize`. Matching children
include `match`, `regex`, `field name="..."`, `srcip`, `dstip`, `srcport`,
`dstport`, `user`, `program_name`, `id`, `action`, `status`. Correlation
children: `if_sid`, `if_group`, `if_matched_sid`, `if_matched_group`,
`if_level`. "Same/different" children: `same_srcip`, `same_dstip`, `same_user`,
`same_dstport`, and a `different_*` variant of each. Metadata: `description`
(supports `$(field)` interpolation), `group`, `mitre`, `options`
(`no_full_log`, `alert_only`).
(https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/rules.html)

Field naming note: the current docs use **`same_srcip`**, not the legacy OSSEC
`same_source_ip`. Use `same_srcip`.

**Rule level table (0-15).** Verified verbatim from
https://documentation.wazuh.com/current/user-manual/ruleset/rules/rules-classification.html:

```
 0  Ignored                       no action, not shown in dashboard, scanned first
 2  System low priority notice    no security relevance
 3  Successful/authorized events  successful login, firewall allow
 5  User-generated error          missed password, denied action; alone, no relevance
 6  Low relevance attack          worm/virus with no effect; frequent IDS events
 7  "Bad word" matching           "bad", "error"; may have some relevance
 8  First time seen               first-time events, sniffer activation
 9  Error from invalid source     login as unknown user / from invalid source
10  Multiple user-generated errs  multiple bad passwords / failed logins  <- brute force
11  Integrity checking warning    binary modification, rootkit
12  High importance event         error/warning from system/kernel; attack on an app
13  Unusual error (high import.)   matches a common attack pattern most of the time
14  High importance security evt   triggered with correlation, indicates an attack
15  Severe attack                  no chance of false positives, immediate attention
```

Two caveats to raise proactively (they signal you read the table): the `level`
attribute accepts 0-16 but the table has no level 1 and no level 16, and the
rules index page says "0 to 16 (severe attack)" while the classification table
tops out at 15. Treat 15 as the top documented severity; levels 1 and 16 are
UNVERIFIED.

**Custom rule ID range.** "Use ID numbers between 100000 and 120000 for custom
rules to avoid conflicts with out-of-the-box system rules."
(https://documentation.wazuh.com/current/user-manual/ruleset/rules/custom.html)
A precise reservation table for Wazuh's own IDs beyond this is UNVERIFIED.

**Stateful correlation (this is our brute-force / scan engine, expressed
Wazuh-natively).** Documented example, verbatim:

```xml
<rule id="50180" level="10" frequency="8" timeframe="120" ignore="60">
  <if_matched_sid>50125</if_matched_sid>
  <description>MySQL: Multiple errors.</description>
</rule>
```

Rule fires at level 10 when rule 50125 matched 8 times in 120 seconds, then
stays quiet 60s. Add `<same_srcip/>` to scope the count to one source. The live
sshd walkthrough confirms rule 5710 (level 5) per failure escalates to rule
5712 (level 10) "After eight matching events from the same source IP within two
minutes". The alert carries a `firedtimes` counter.
(https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/rules.html,
https://documentation.wazuh.com/current/user-manual/ruleset/testing.html)
The folklore "real threshold is frequency+1" is UNVERIFIED; test before claiming.

**Decoders and standard field names.** Static (standard) fields:
`srcip, dstip, srcport, dstport, srcuser, dstuser (alias user), protocol,
action, status, id, url, data, extra_data, system_name, hostname, location`.
"Any other string becomes a dynamic field." Wazuh has a built-in JSON decoder;
nested keys use dot notation in `<field name="alert.action">`.
(https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/decoders.html,
https://documentation.wazuh.com/current/user-manual/ruleset/json-decoder.html)

**MITRE integration.** `<mitre><id>T1110</id></mitre>` inside a rule; Wazuh
enriches the alert with a `mitre` object of `id`, `tactic`, `technique` arrays.
So we supply only technique IDs.
(https://documentation.wazuh.com/current/user-manual/ruleset/mitre.html)

**Real alert JSON to imitate** (SSH brute force, rule 5712), verbatim from
testing.html:

```json
{
  "timestamp": "2023-04-25T13:51:36.409000Z",
  "rule": {
    "level": 10, "description": "sshd: brute force ...", "id": "5712",
    "firedtimes": 1, "frequency": 8,
    "groups": ["syslog","sshd","authentication_failures"],
    "mitre": {"id":["T1110"],"tactic":["Credential Access"],"technique":["Brute Force"]}
  },
  "agent": {"id":"000","name":"centos7"},
  "id": "1682430696.3725",
  "full_log": "Oct 15 21:07:00 linux-agent sshd[29205]: Invalid user blimey from 18.18.18.18 port 48928",
  "data": {"srcip":"18.18.18.18","srcport":"48928","srcuser":"blimey"},
  "location": "master->/var/log/syslog"
}
```

Structural facts: `rule.id` is a **string**, `rule.level` an int, decoded fields
under `data.*`, raw line under `full_log`, MITRE arrays under `rule.mitre`.

**CSV ingestion.** No `csv` log_format exists. Supported values include
`syslog, json, multi-line, iis, snort-full, audit, command`. Two routes for our
CSV: convert to JSON and use the built-in json decoder (recommended), or read as
plain text with a custom `<regex>`+`<order>` decoder.
(https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/localfile.html)

### A2. Splunk

**Common Information Model field names** (for output schema alignment).
Network Traffic model (`All_Traffic`): `action` (allowed/blocked/teardown),
`app` (the L7 protocol), `bytes/bytes_in/bytes_out`, `src/dest`,
`src_port/dest_port`, `transport` (tcp/udp/icmp = L4), `protocol` (L3),
`direction`, `user`, `dvc`.
(https://help.splunk.com/en/splunk-cloud-platform/common-information-model/6.0/data-models/network-traffic)
Authentication model: `action` (success/failure/pending/error), `app`, `src`,
`dest`, `user`, `src_user`, `signature`.
(https://help.splunk.com/en/splunk-cloud-platform/common-information-model/6.0/data-models/authentication)
DNS model (`Network_Resolution`): `query`, `query_type`, `record_type`,
`answer`, `reply_code`, `src`, `dest`.
(https://help.splunk.com/en/splunk-cloud-platform/common-information-model/6.0/data-models/network-resolution-dns)

**Load-bearing nuance: CIM puts the application protocol in `app` (L7),
`transport` is L4, `protocol` is L3.** ECS is the opposite (L7 in
`network.protocol`). Our schema must not collide the two.

**Notable events and urgency.** Urgency = f(event severity, asset/identity
priority), a lookup matrix, using the higher of asset vs identity priority.
Severity and urgency vocab: informational/low/medium/high/critical.
(https://help.splunk.com/en/splunk-enterprise-security-7/user-guide/7.3/incident-review/how-urgency-is-assigned-to-notable-events-in-splunk-enterprise-security)

**Risk-Based Alerting.** Risk score bands: 20 Info, 40 Low, 60 Medium, 80 High,
100 Critical. A "risk notable" fires when accumulated risk on an object crosses
a threshold. Default rules: "risk_score summed > 100 over 24h", and ">= 3
distinct MITRE tactics AND >= 4 sources over 7 days".
(https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.1/risk-based-alerting/risk-scoring-in-splunk-enterprise-security,
https://help.splunk.com/en/splunk-enterprise-security-7/risk-based-alerting/7.3/identify-threat/default-risk-incident-rules-in-splunk-enterprise-security)
This is the model for our entity risk layer: individual detections stay
low-score, only *convergence* on one entity pages an analyst. That is how 1M
rows avoid producing 1M alerts.

### A3. CrowdStrike Falcon

CrowdStrike's own API docs are login-gated; schema verified from Microsoft
Sentinel's `CrowdStrikeDetections` table and Elastic's CrowdStrike integration
(stated as secondary mirrors).
Detection object carries: `Severity` (int) + `SeverityName`, `Confidence`
(0-100), the **tactic / technique / objective** triple (`Tactic`+`TacticId`,
`Technique`+`TechniqueId`, `Objective`), and process-tree fields
(`ParentDetails`, `ChildProcessIds`, `TreeId`, `Cmdline`) that feed the Incident
Workbench. Severity bands: 0-19 Informational, 20-39 Low, 40-59 Medium, 60-79
High, 80-100 Critical.
(https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/crowdstrikedetections,
https://www.elastic.co/docs/reference/integrations/crowdstrike)
The takeaway for us: the tactic/technique/objective triple and a 0-100 severity
scale are worth mirroring as an alternative view of our findings.

### A4. Elastic Common Schema (for the second half of our dual output mapping)

`source.ip`, `source.port`, `destination.ip`, `destination.port`,
`network.transport` (L4), `network.protocol` (L7), `event.category`,
`event.type`, `event.outcome` (constrained: failure/success/unknown),
`event.action` (free-form), `user.name`, `dns.question.name`,
`dns.question.subdomain`, `dns.question.registered_domain`,
`process.command_line`, `process.name`, `rule.name`, `threat.tactic.name`,
`threat.technique.id`, `related.ip[]`, `related.user[]`.
`event.category` is a constrained vocabulary including
`authentication, network, dns` (via `intrusion_detection`), `process`,
`intrusion_detection`. `event.kind` includes `alert`.
(https://www.elastic.co/guide/en/ecs/current/ecs-network.html,
https://www.elastic.co/guide/en/ecs/current/ecs-allowed-values-event-category.html,
https://www.elastic.co/guide/en/ecs/current/ecs-allowed-values-event-outcome.html,
https://www.elastic.co/guide/en/ecs/current/ecs-threat.html)
Populate `related.ip[]` and `related.user[]` on every alert for pivoting.

### A5. Sigma and MITRE ATT&CK conventions

**Sigma schema.** Required: `title`, `logsource`, `detection`. Optional include
`id` (UUIDv4), `status` (stable/test/experimental/deprecated/unsupported),
`level` (informational/low/medium/high/critical), `description`, `references`,
`author`, `date`, `tags`, `falsepositives`, `fields`. Modifiers: `contains`,
`startswith`, `endswith`, `re`, `base64offset`, `all`, `cidr`, `windash`.
Condition supports `and/or/not`, grouping, `1 of selection*`, `all of them`.
(https://github.com/SigmaHQ/sigma-specification, specification/sigma-rules-specification.md
and specification/sigma-appendix-modifiers.md)

**Sigma correlations** (the N-in-T mechanism): types `event_count`,
`value_count`, `temporal`, `temporal_ordered`; fields `type`, `rules`,
`group-by`, `timespan` (`10m`, `1h`), `condition` (`gte: 10`).
(https://github.com/SigmaHQ/sigma-specification, specification/sigma-correlation-rules-specification.md)

**Real Sigma DNS rule** (`rules/network/dns/net_dns_susp_b64_queries.yml`):
selection `query|contains: '==.'`, dual-tagged `attack.t1048.003` +
`attack.t1071.004`, level medium. This is exactly the technique pair our DNS
detector should emit.
(https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/network/dns/net_dns_susp_b64_queries.yml)

**Sigma has no stock SSH brute-force rule** (verified by listing
`rules/linux/builtin/sshd/`, which holds one non-bruteforce rule). Brute force
is a Sigma Correlation. Wazuh's `0095-sshd_rules.xml` is the mature reference.

**MITRE technique IDs (exact, each from attack.mitre.org):**

```
T1046      Network Service Discovery            Discovery (TA0007)
T1595      Active Scanning                      Reconnaissance (TA0043)
 T1595.001 Scanning IP Blocks
T1110      Brute Force                          Credential Access (TA0006)
 T1110.003 Password Spraying
 T1110.004 Credential Stuffing
T1071.004  Application Layer Protocol: DNS      Command and Control (TA0011)
T1048.003  Exfil Over Unencrypted Non-C2 Proto  Exfiltration (TA0010)
T1572      Protocol Tunneling                   Command and Control (TA0011)
T1568.002  Dynamic Resolution: DGA              Command and Control (TA0011)
T1059.001  Command/Scripting Interpreter: PS    Execution (TA0002)
T1027      Obfuscated Files or Information       Stealth (TA0005, was Defense Evasion)
 T1027.010 Command Obfuscation
T1105      Ingress Tool Transfer                Command and Control (TA0011)
T1571      Non-Standard Port                    Command and Control (TA0011)
```

Notes: T1046 is internal Discovery; T1595 is external Reconnaissance. Pick per
event based on whether the scan source is internal or external. MITRE does not
name port 4444 on the T1571 page (that is a Metasploit convention, a tool fact
not an ATT&CK fact). The encoded-PowerShell angle is T1027.010.
(https://attack.mitre.org/techniques/T1046/, /T1110/, /T1071/004/, /T1048/003/,
/T1059/001/, /T1027/, /T1571/, and https://attack.mitre.org/tactics/enterprise/)

### A6. Detection thresholds (defaults we adopt, each sourced)

```
Vertical port scan      >= 15 distinct dest ports, one src -> one dst, 5 min
                        (Zeek scan.zeek port_scan_threshold=15.0, interval=5min)
Horizontal sweep        >= 25 distinct dest hosts, one src -> one dst_port, 5 min
                        (Zeek addr_scan_threshold=25.0)
Distributed scan        key by DEST; >= 25 distinct src converging; negative
                        responses (Snort port_scan nets=25, ports=25, rejects=15;
                        Snort "tcp_dist" = many-to-one table)
DNS tunneling           Shannon entropy(subdomain) > 3.0 AND subdomain length
                        > 20 AND per-domain query-length z-score > 2; NEVER
                        entropy alone (cloud/CDN FP). Label <= 63, FQDN <= 253
                        as sanity bounds (RFC 1035).
                        (Splunk URL Toolbox: entropy>3, avg_sublen>20; Splunk
                        ESCU DNS-length-stdev; SANS/Hurricane FP caveat)
Brute force             key by (dst,user); >= 5-10 consecutive failures, seconds
                        (Elastic runs=5 @5s Windows, runs=10 @15s SSH)
Password spraying       key by src; >= 10 distinct users (low floor) up to >= 30
                        (3-sigma), success/failure < 0.25
                        (Splunk ESCU b6391b15..., 086ab581...)
Distributed spray       distinct_users > 30 AND distinct_src > 30 (Splunk ESCU)
```

Sources, verbatim configs: Snort 3 `port_scan` `ps_module.cc`
(scans=100, rejects=15, nets=25, ports=25); Zeek `scan.zeek` v3.2.4
(`port_scan_threshold=15.0`, `addr_scan_threshold=25.0`, both 5 min) — note
`scan.zeek` was later deprecated from core Zeek but the numbers are the
authoritative classic defaults; RFC 1035 for DNS limits; Splunk URL Toolbox
blog and ESCU research rules; Elastic detection-rules TOML. All URLs in the
agent transcript; key ones:
https://github.com/snort3/snort3/blob/master/src/network_inspectors/port_scan/ps_module.cc,
https://github.com/zeek/zeek/blob/v3.2.4/scripts/policy/misc/scan.zeek,
https://www.rfc-editor.org/rfc/rfc1035,
https://www.splunk.com/en_us/blog/security/domain-detection-levenshtein-shannon.html,
https://research.splunk.com/application/086ab581-8877-42b3-9aee-4a7ecb0923af/

**Our data is the distributed case for both scan and brute force** (see SPEC
section 3.2), so our primary rules key on `dst` and count distinct `src` by
subnet. That is precisely the aggregation Wazuh's `same_srcip` cannot express,
which is the tool's reason to exist.

---

## Section B: Design references

Method tags: [EXTRACTED] from live CSS/JS, [COMPUTED] a ratio calculated this
session, [JUDGEMENT] design recommendation. No guessed hex or typeface.
5 of 6 sites loaded. `sandracretes.com` does not exist; the real site is
**sandracreates.com** (creates, not cretes).

| Site | What it is | Steal | Leave |
|---|---|---|---|
| sandracreates.com | Warm light Framer portfolio; Vastago Grotesk + Azeret Mono; one red-orange `#ff4824` on cream | "one hot accent on a neutral field" discipline | light theme, candy pinks |
| heatbureau.com | Cream/black editorial; Neue Montreal + DM/Fragment Mono; tight uppercase | mono label pairing + tight uppercase micro-caps | neon secondary palette |
| clicktokeep.com | Editorial indigo `#2B328C`; grotesk vs Libre Baskerville serif | grotesk-vs-serif for section intros | Wix DOM weight |
| kargo-studio.com | Near-monochrome; Mozaic GEO Thin->Extra-Black (weight 210-880) | **weight, not color, creates hierarchy** (the core thesis) | 7px UI text, rolling-hover |
| wairk.fr | Dark charcoal `#282828`; Graphik + Cousine mono; one orange `#FF4D00` | **charcoal (not black) + one accent** | 110px hero |
| higgsfield.ai | Real dark product UI; Space Grotesk + IBM Plex Mono; surface ramp `#0f1113`->`#23262a`, acid-lime `#d1fe17` | the **surface architecture** + grotesk/mono split | acid-lime as a large fill (halation) |

Motion note [EXTRACTED]: no GSAP, no Lenis on any of the six. The three Framer
sites use Framer Motion. Implication: our dashboard needs no heavy motion library.

**Through-line:** grotesk display + monospace data, hierarchy from weight/size
not decoration, charcoal-not-black grounds, exactly one accent. That is the
borrowable DNA. It also happens to be exactly what a dense triage grid needs.

**The tension, resolved [JUDGEMENT].** Portfolio sites earn presence through
scale and negative space, luxuries a triage grid cannot afford. So we transplant
the *confidence*, not the *whitespace*: Kargo's Thin-vs-Extra-Black drama is
reproduced at 12-13px (mono uppercase 11px labels against 600-weight values).
Editorial whitespace is spent once, at the top (one ~48px KPI number), then the
grid gets to work.

**SOC dashboard layout patterns** (from vendor docs).
- Above the fold, universally: KPI count strip -> severity/urgency breakdown ->
  time trend -> alert table. "How many, how bad, is it rising, then the list."
- Splunk ES Security Posture: Key indicators, Findings by urgency, Findings over
  time, Top findings (+ sparkline), Top sources (+ sparkline).
- Elastic alert table: trend histogram on top, "group alerts by" up to 3 fields,
  bulk triage bar (change status / assign / tag / add to case / investigate in
  timeline), expandable row flyout.
- Wazuh (the team's tool): Threat Detection modules MITRE ATT&CK (Framework /
  Intelligence / Events tabs), Threat Hunting, Security Events, Rules, Decoders,
  Discover. Severity is the rule `level` (0-15). Match our severity chip to that.
- Defender incident drill-down = Overview / Attack Story graph / Alerts /
  Evidence and Response / Entities. Good model for our incident view.
- Charts that earn place: time-series line/area (volume), horizontal bar (top
  talkers/rules), sparkline (per row), node-link (attack path / scan fan-in).
- Cut: pie/donut/gauge (including Splunk's urgency pies), 3D, radial "cyber"
  rings, geo-map pins that hide the fan-in structure.

**Accessibility (the load-bearing computed result).**
A colour-only 4-step severity scale cannot simultaneously keep adjacent steps
separable under deuteranopia and hold 4.5:1 small-text contrast on near-black.
[COMPUTED] traffic-light red `#FF0000` vs green `#00C853` collapse to 1.16:1
separation under deuteranopia. Therefore severity is encoded on colour AND a
shape/label, always. Every real SOC does this.
WCAG minimums [EXTRACTED, W3C]: text 4.5:1, large text 3:1, non-text UI /
chart marks 3:1.
(https://www.w3.org/WAI/WCAG22/Understanding/contrast-minimum.html,
https://www.w3.org/WAI/WCAG22/Understanding/non-text-contrast.html)

Full colour system with computed contrast ratios lives in DESIGN.md.

---

## Section C: Skills and repo inventory

### C1. Plugins (verified this session)

- **claude-mem** (`thedotmack/claude-mem`, Apache-2.0, very active). It is 5
  lifecycle hooks + a background Bun HTTP worker + SQLite/Chroma + an MCP server,
  with cloud sync to cmem.ai. 92% single-maintainer, 13 major versions in ~10
  months. **Verdict: SKIP.** For a 2-day graded security project the value
  (long-horizon multi-project memory) does not apply, and adding a third-party
  hook that observes every tool call plus a cloud-sync daemon is a supply-chain
  liability you would have to defend in review. Native memory + `session-log.md`
  + the installed `save-session` / `resume-session` skills replace it at zero
  risk. Install command, if ever wanted: `npx claude-mem install`.
- **superpowers** (`obra/superpowers`, MIT, 3.7 MB). Real. Install
  `/plugin install superpowers@claude-plugins-official` is correct. But it ships
  *skills*, not the commands the pack named: real names are `/brainstorming`,
  `/writing-plans`, `/executing-plans`, plus `test-driven-development` and
  `systematic-debugging`. **`/superpower` and `/find` do not exist in it**; do
  not build a workflow that depends on `/find`.

### C2. vendor/ manifest (clone in build phase, not now)

| Repo | Command | Size | License | Use |
|---|---|---|---|---|
| SigmaHQ/sigma | `git clone --depth 1 https://github.com/SigmaHQ/sigma.git vendor/sigma` | ~30 MB shallow | DRL 1.1 (rules) | rule format + DNS/network reference corpus; default branch `master` |
| wazuh/wazuh (sparse) | `git clone --depth 1 --branch master --filter=blob:none --sparse https://github.com/wazuh/wazuh.git vendor/wazuh` then `git -C vendor/wazuh sparse-checkout set ruleset` | ~25 MB sparse (full 521 MB) | GPLv2 (confirm before redistributing) | `0095-sshd_rules.xml`, decoders; the SSH-bruteforce reference |
| MITRE ATT&CK | `pip install mitreattack-python` (do not clone the 125 MB STIX repo) | 15 MB | Apache-2.0 | technique ID -> name for rule validation |
| SigmaHQ/sigma-cli | `pip install sigma-cli` | n/a | LGPL-2.1 | `sigma check` = machine-checkable rule quality gate |

Corrections baked in: `wazuh/wazuh-ruleset` is **archived** (last push 2024-09),
do not clone it; and a naive `git clone wazuh/wazuh` lands on the `main`/5.x
branch where `ruleset/rules/` is empty. Rules are on `master`. Recommended
against (junk-drawer): Atomic Red Team, Elastic detection-rules, Splunk
security_content, ET rules, attack-stix-data. Three repos + two pip installs is
the right size.

### C3. Skill-to-phase map

Use:

| Phase | Skill | Why |
|---|---|---|
| Scaffold | `project-init` | repo skeleton, once |
| Research (domain) | `analyzing-network-traffic-for-incidents` | defines what a detection should look for: C2, exfil, lateral movement |
| Research (domain) | `performing-network-traffic-analysis-with-zeek` | Zeek conn/dns log shapes drive our parser schema |
| Detection algorithms | `analyzing-network-flow-data-with-netflow` | port scan, exfil, beaconing via statistics |
| Threshold tuning | `implementing-network-traffic-baselining` | how to pick thresholds without drowning in FPs |
| Build | `feature-dev` | codebase-aware feature work |
| Testing | `test-coverage` | detection rules need TP and FP fixtures |
| Review | `python-review` | highest-value review skill (project is Python) |
| Dashboard | `dataviz` (bundled) | correct skill for charts |
| Frontend | `frontend-design` | for the HTML dashboard build |
| Hardening | `security-scan`, `code-review`, `quality-gate` | security-scan on a security tool reads well; CI gate |
| Docs | `update-docs` | final deliverable |
| Cross-cutting | `save-session` + `resume-session` | the claude-mem replacement, already installed |

Do NOT use: the ~150 `exploiting-*`, `conducting-*`, `performing-*` (offensive),
`building-red-team-*`, `testing-*` skills. They are red-team TTP execution guides,
wrong domain for a blue-team detector, and a live context-pollution hazard (the
words "brute force" in our own work could pull in hashcat/kerberoasting skills).
Also skip `building-vulnerability-dashboard-with-defectdojo` (vuln management,
wrong domain), `ui-ux-pro-max` / `taste-skill` / `artifact-design` (frontend
polish noise for a detection grade), `multi-plan` (overkill). `frontend-design`
is the one UI skill we keep, only for the dashboard build.

---

## Status

This research grounds the requirements in `docs/PRD.md`.
