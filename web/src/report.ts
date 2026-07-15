/**
 * The contract with Python.
 *
 * These types mirror the dict that `eventiq.report.build_report` produces and
 * that `POST /analyze` returns. The SPA reads nothing else: no side channels, no
 * derived state smuggled in from the server. That is what keeps this renderer
 * and the static Jinja export from drifting apart.
 *
 * If a field changes shape in Python, change it here and in the Jinja template
 * in the same commit. `tests/unit/test_render.py` fails on drift.
 */

export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO'

/** A [label, count] pair. Python emits tuples, JSON makes them arrays. */
export type Tally = [string, number]

export interface ReportInput {
  file: string
  rows: number
  malformed: number
  span_start: string
  span_end: string
  /** 'complete' when every optional canonical field was present. */
  schema: string
  missing_optional: string[]
}

export interface Summary {
  by_severity: Partial<Record<Severity, number>>
  distinct_rules: number[]
  alert_count: number
  incident_count: number
  entities_at_risk: number
  flagged_events: number
  benign_events: number
}

export interface Overview {
  total_events: number
  distinct: {
    source_ips: number
    destination_ips: number
    usernames: number
    domains: number
    services: number
  }
  protocol: Record<string, number>
  status: Record<string, number>
  top_services: Tally[]
  top_source_ips: Tally[]
  top_destination_ips: Tally[]
  top_usernames: Tally[]
  top_domains: Tally[]
  top_dstports: Tally[]
  /** [day, count] per calendar day across the file's span. */
  daily_volume: Tally[]
  bytes: { sent: number; received: number }
  flagged_events: number
  benign_events: number
  flagged_pct: number
}

export interface Category {
  rule_id: number
  category: string
  basis: string
  severity: Severity
  events: number
  alerts: number
  mitre: string[]
}

export interface Incident {
  id: string
  /** Exact relationship to Alert.rule.id; never infer it from display text. */
  rule_id: number
  title: string
  category: string
  basis: string
  primary_entity: string
  severity: Severity
  risk_score: number
  techniques: string[]
  first_seen: string
  last_seen: string
  alert_count: number
  event_count: number
  affected_count: number
  affected_entities: string[]
  narrative: string
}

export interface EntityRisk {
  entity: string
  risk_score: number
  severity: Severity
  contributing_rules: number[]
  techniques: string[]
  alert_count: number
}

export interface Alert {
  rule: {
    id: number
    level: number
    description: string
    mitre: { id: string[] }
  }
  title: string
  severity: Severity
  risk_score: number
  entity: string
  first_seen: string
  last_seen: string
  /** Rule-specific detail. Shape varies by detector, so it stays open. */
  data: Record<string, unknown>
  evidence: Record<string, unknown> & { events?: number }
  sample_rows: string[]
  status: string
}

/** A detection we deliberately did NOT build, and why. Honest scoping. */
export interface NotDetected {
  name: string
  reason: string
  numbers: string
}

export interface RuleScore {
  rule_id: number
  campaign: string
  tp: number
  fp: number
  fn: number
  precision: number
  recall: number
  f1: number
  alerts: number
  alerts_valid: number
}

export interface Overall {
  tp: number
  fp: number
  fn: number
  precision: number
  recall: number
  f1: number
}

/**
 * There are THREE label states, not two. Getting this wrong crashes the
 * dashboard, so it is worth spelling out:
 *
 * 1. `Report.validation === null`
 *    The file has no event_type column at all. Nothing to score against.
 * 2. `validation !== null` but `validation.overall === null`
 *    The file HAS an event_type column, but none of its labels are supported
 *    campaigns (generic LOGIN / DNS_QUERY / system_event and the like).
 *    `per_rule` is empty and `naive_failed_login_baseline.precision` is null.
 *    Python calls this label_audit.quality === 'unsupported'.
 * 3. `validation.overall !== null`
 *    Real campaign labels were present and held out, so scores are real.
 *
 * State 2 is the common one for small hand-made test files, and it is exactly
 * the honest-scoping point of this project: an event_type column is not an
 * answer key merely because it exists.
 */
export interface Validation {
  label_audit: {
    quality: string
    scored_rules: number
    known_campaigns_present: string[]
    distinct_labels: number
  }
  /** Empty when no supported campaign label is present. */
  per_rule: Record<string, RuleScore>
  /** Null when there was no supported campaign label to score against. */
  overall: Overall | null
  /** The contrast that makes precision mean something. `precision` is null when
   *  there was no real burst to compare against. */
  naive_failed_login_baseline?: { precision: number | null; note: string }
  unscored: { rule_id: number; note: string; alerts: number }[]
}

export interface Report {
  generated_at: string
  input: ReportInput
  summary: Summary
  overview: Overview
  categories: Category[]
  incidents: Incident[]
  entity_risk: EntityRisk[]
  alerts: Alert[]
  coverage: { rules_enabled: number; scope: string }
  not_detected: NotDetected[]
  /** Absent when the uploaded file carried no labels to score against. */
  validation: Validation | null
}

/** What the server sends instead of a report when analysis fails. */
export interface AnalyzeError {
  error: string
  kind: 'schema' | 'internal'
}

export async function analyze(file: File): Promise<Report> {
  const response = await fetch(`/analyze?name=${encodeURIComponent(file.name)}`, {
    method: 'POST',
    body: file,
  })
  const payload: unknown = await response.json()
  if (!response.ok) {
    const err = payload as AnalyzeError
    throw new Error(err?.error ?? `analysis failed (HTTP ${response.status})`)
  }
  return payload as Report
}
