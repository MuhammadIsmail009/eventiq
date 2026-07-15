# Sigma and YARA scope

Checked against the official sources on 2026-07-14.

## What is implemented

EventIQ has its own streaming detector interface. It does not claim to be a
general Sigma runtime. The default configuration enables two conservative
Windows command behaviours derived from current SigmaHQ rules:

| EventIQ rule | Upstream Sigma rule | Required command evidence | MITRE |
| --- | --- | --- | --- |
| 100700 Bitsadmin download | [d059842b-6b9d-4ed1-b5c3-5b89143c6ede](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_bitsadmin_download.yml) | `bitsadmin` plus `/transfer`, or `/create`/`/addfile` plus HTTP | T1105 |
| 100710 Certutil download | [19b08b1c-861d-4e75-a1ef-ea0c1baf202b](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_certutil_download.yml) | `certutil` plus URL-capable flag and HTTP | T1105 |

The upstream rules require a Windows process-creation log source and identify
the executable through `Image` or `OriginalFileName`. EventIQ's normalized CSV
does not expose those fields separately, so its native mapping requires the
utility name in the command line. This is stricter than matching download flags
alone and prevents unrelated commands from firing.

Both mappings have positive and negative regression tests. Normal utility use
such as `bitsadmin /list` and `certutil -hashfile` stays quiet.

`eventiq export --sigma` emits Sigma documents that retain the upstream rule
IDs in `related` metadata. `eventiq export --wazuh` emits equivalent PCRE2
command rules for a deployment whose decoder maps a `command` field.

## Why the full Sigma repository is not bundled

Sigma rules declare a `logsource`, detection fields, conditions and metadata.
They become useful only after a pipeline maps a product's fields and semantics
to the Sigma taxonomy. The official project recommends pySigma for integration.
Loading thousands of YAML files without those mappings would make most rules
inapplicable and would overstate coverage.

Sources:

- [Sigma rules documentation](https://sigmahq.io/docs/basics/rules.html)
- [Sigma rule specification](https://sigmahq.io/sigma-specification/specification/sigma-rules-specification.html)
- [SigmaHQ main rule repository](https://github.com/SigmaHQ/sigma)
- [pySigma](https://github.com/SigmaHQ/pySigma)

A future native Sigma import should add explicit logsource eligibility, field
mapping, unsupported-modifier rejection, rule-pack versioning, and regression
fixtures before it is enabled.

## Why YARA is not used on ordinary log CSVs

YARA applies rules to a target file, folder or process and matches content or
binary structure. It is appropriate when an investigation has a malware sample,
memory, or an artifact file. It is not a substitute for behavioral aggregation
over authentication, DNS and network events.

EventIQ therefore does not run YARA over the uploaded CSV and call matched
text a malware finding. An optional artifact-scanning feature can be added later
if a log record points to an accessible file and the operator explicitly enables
that separate scan.

Sources:

- [YARA getting started](https://yara.readthedocs.io/en/stable/gettingstarted.html)
- [YARA command-line targets](https://yara.readthedocs.io/en/stable/commandline.html)

## Update policy

Review the two upstream rule IDs quarterly or before a release. If SigmaHQ
changes a condition, update the native mapping, its export, this document and
the positive/negative tests in one change. Do not add an upstream rule merely
because it is popular. Add it only when EventIQ has the required fields and a
benign fixture that proves the false-positive boundary.
