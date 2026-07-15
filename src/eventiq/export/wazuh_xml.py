"""Generate a Wazuh rule set from the EventIQ config.

The distributed detections (scan, brute force) become Wazuh frequency rules that
count different source IPs against the same destination, which is Wazuh's native
way to express "many sources converging on one host". The content detections
(PowerShell, suspicious domain, C2 port) become field/pcre2 matches. Rule ids sit
in the 100000-120000 custom band. Deploying these needs a decoder that maps this
CSV's columns onto the srcip/dstip/dstport/command fields, which is the team's
call (PRD non-goal); the header says so.
"""

from __future__ import annotations

from xml.sax.saxutils import escape

from ..config import Config

_HEADER = """<!--
  EventIQ generated Wazuh rules. Ids 100000-120000 (custom band).
  These mirror the EventIQ detections. Two caveats a reviewer should know:
    1. They assume a decoder exposes srcip, dstip, dstport, srcuser, command,
       protocol for the ingested logs. Writing that decoder is a deployment step.
    2. DNS tunneling here is approximated by a long-random-label regex; EventIQ
       itself uses Shannon entropy plus unique-subdomain volume, which a static
       Wazuh rule cannot compute. Treat this rule as a coarse net.
-->"""


def _mitre(ids: list[str]) -> str:
    inner = "".join(f"\n    <id>{escape(i)}</id>" for i in ids)
    return f"  <mitre>{inner}\n  </mitre>"


def build_wazuh_xml(config: Config) -> str:
    ps = config.port_scan
    bf = config.brute_force
    dt = config.dns_tunnel
    sd = config.suspicious_domain
    c2 = config.c2_port
    cbf = config.classic_brute_force
    cps = config.classic_port_scan
    spray = config.password_spray
    lm = config.lateral_movement

    parts: list[str] = [_HEADER, '<group name="eventiq,network,">', ""]

    # --- Brute force: base failed-auth rule + frequency of different sources ---
    ports_re = "|".join(str(p) for p in bf.ports)
    parts.append(
        f'''  <rule id="100190" level="3">
    <field name="status">FAILED</field>
    <field name="dstport">^(?:{ports_re})$</field>
    <description>Failed authentication on a monitored service (base)</description>
  </rule>

  <rule id="{100100}" level="{bf.level}" frequency="{bf.min_distinct_sources}" timeframe="600">
    <if_matched_sid>100190</if_matched_sid>
    <same_dstip />
    <different_srcip />
    <description>Distributed brute force: {bf.min_distinct_sources}+ distinct sources failing auth on one host</description>
{_mitre(bf.mitre)}
  </rule>
'''
    )

    # --- Port scan: base refused-connection rule + frequency of different sources ---
    refused_re = "|".join(escape(s) for s in ps.refused_statuses)
    parts.append(
        f'''  <rule id="100290" level="3">
    <field name="status">^(?:{refused_re})$</field>
    <description>Refused connection attempt (base)</description>
  </rule>

  <rule id="{100200}" level="{ps.level}" frequency="{ps.min_distinct_sources}" timeframe="600">
    <if_matched_sid>100290</if_matched_sid>
    <same_dstip />
    <different_srcip />
    <description>Distributed port scan: {ps.min_distinct_sources}+ distinct sources refused by one host</description>
{_mitre(ps.mitre)}
  </rule>
'''
    )

    # --- Classic single-source detections (Phase 7) ---
    # These map cleanly onto Wazuh frequency rules using the native same_*/
    # different_* correlation options. Field options verified against the Wazuh
    # Rules Syntax reference (documentation.wazuh.com).
    lateral_ports_re = "|".join(str(p) for p in lm.ports)
    parts.append(
        f'''  <rule id="100119" level="3">
    <field name="status">FAILED</field>
    <description>Failed authentication, any service (base)</description>
  </rule>

  <rule id="{100110}" level="{cbf.level}" frequency="{cbf.min_failures}" timeframe="{cbf.window_seconds}">
    <if_matched_sid>100119</if_matched_sid>
    <same_srcip />
    <same_dstip />
    <description>Classic brute force: {cbf.min_failures}+ failed auth from one source to one host</description>
{_mitre(cbf.mitre)}
  </rule>

  <rule id="{100120}" level="{spray.level}" frequency="{spray.min_usernames}" timeframe="{spray.window_seconds}">
    <if_matched_sid>100119</if_matched_sid>
    <same_srcip />
    <same_dstip />
    <different_srcuser />
    <description>Password spray (one source, {spray.min_usernames}+ distinct usernames on one host)</description>
{_mitre(spray.mitre)}
  </rule>

  <!-- Password spray shape B (many sources onto one account). Wazuh cannot
       express the "< max_sources" upper bound the native rule uses to hand the
       large distributed campaign to rule 100100, so this is a coarser net. -->
  <rule id="100121" level="{spray.level}" frequency="{spray.min_sources}" timeframe="86400">
    <if_matched_sid>100119</if_matched_sid>
    <same_dstip />
    <same_srcuser />
    <different_srcip />
    <description>Password spray ({spray.min_sources}+ distinct sources failing one account on one host)</description>
{_mitre(spray.mitre)}
  </rule>

  <rule id="100219" level="3">
    <field name="dstport">^\\d+$</field>
    <description>Connection attempt carrying a destination port (base)</description>
  </rule>

  <rule id="{100210}" level="{cps.level}" frequency="{cps.min_ports}" timeframe="{cps.window_seconds}">
    <if_matched_sid>100219</if_matched_sid>
    <same_srcip />
    <same_dstip />
    <different_dstport />
    <description>Classic port scan: one source touching {cps.min_ports}+ ports of one host</description>
{_mitre(cps.mitre)}
  </rule>

  <rule id="100139" level="3">
    <field name="status">FAILED</field>
    <field name="dstport">^(?:{lateral_ports_re})$</field>
    <description>Failed auth on a remote-service port (base)</description>
  </rule>

  <rule id="{100130}" level="{lm.level}" frequency="{lm.min_hosts}" timeframe="{lm.window_seconds}">
    <if_matched_sid>100139</if_matched_sid>
    <same_srcip />
    <different_dstip />
    <description>Lateral movement: one source failing auth across {lm.min_hosts}+ hosts on remote-service ports</description>
{_mitre(lm.mitre)}
  </rule>
'''
    )

    # --- DNS tunneling: coarse long-random-label regex ---
    parts.append(
        f'''  <rule id="{100300}" level="{dt.level}">
    <field name="domain">[a-z0-9]{{{dt.min_label_len},}}\\.</field>
    <description>Possible DNS tunneling: long random subdomain label (coarse; EventIQ uses entropy + volume)</description>
{_mitre(dt.mitre)}
  </rule>
'''
    )

    # --- Suspicious domains: IOC alternation ---
    iocs_re = "|".join(escape(d.replace(".", "\\.")) for d in sd.iocs) or "(?!x)x"
    parts.append(
        f'''  <rule id="{100400}" level="{sd.level}">
    <field name="domain">^(?:{iocs_re})$</field>
    <description>Connection to known-suspicious domain (IOC list)</description>
{_mitre(sd.mitre)}
  </rule>
'''
    )

    # --- Malicious PowerShell: command patterns ---
    parts.append(
        f'''  <rule id="{100500}" level="{config.powershell.level}">
    <field name="command">(?i)(-enc|downloadstring|-w\\s+hidden|-windowstyle\\s+hidden|-e\\s+bypass|-executionpolicy\\s+bypass)</field>
    <description>Malicious PowerShell pattern (encoded / download cradle / hidden / bypass)</description>
{_mitre(config.powershell.mitre)}
  </rule>
'''
    )

    # --- C2 port ---
    c2_ports_re = "|".join(str(p) for p in c2.ioc_ports)
    parts.append(
        f'''  <rule id="{100600}" level="{c2.level}">
    <field name="dstport">^(?:{c2_ports_re})$</field>
    <description>Traffic to known command-and-control port</description>
{_mitre(c2.mitre)}
  </rule>
'''
    )

    # --- SigmaHQ-derived command download behaviours ---
    sc = config.sigma_commands
    if "bitsadmin_download" in sc.enabled_rules:
        parts.append(
            fr'''  <rule id="{100700}" level="{sc.level}">
    <field name="command" type="pcre2">(?i)\bbitsadmin(?:\.exe)?\b(?:(?=.*\s/transfer\s)|(?=.*\s/(?:create|addfile)\s)(?=.*https?://)).*</field>
    <description>SigmaHQ-derived Bitsadmin file download command</description>
{_mitre(sc.mitre)}
  </rule>
'''
        )
    if "certutil_download" in sc.enabled_rules:
        parts.append(
            fr'''  <rule id="{100710}" level="{sc.level}">
    <field name="command" type="pcre2">(?i)\bcertutil(?:\.exe)?\b(?=.*(?:urlcache|verifyctl|\surl\s))(?=.*https?://).*</field>
    <description>SigmaHQ-derived Certutil URL download command</description>
{_mitre(sc.mitre)}
  </rule>
'''
        )

    parts.append("</group>\n")
    return "\n".join(parts)
