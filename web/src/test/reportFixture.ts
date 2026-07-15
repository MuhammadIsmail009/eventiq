import type { Report } from '../report'

export function makeReport(): Report {
  return {
    generated_at: '2026-07-15T12:00:00Z',
    input: {
      file: 'fixture.csv',
      rows: 42,
      malformed: 0,
      span_start: '2026-07-15T00:00:00Z',
      span_end: '2026-07-15T01:00:00Z',
      schema: 'complete',
      missing_optional: [],
    },
    summary: {
      by_severity: {},
      distinct_rules: [],
      alert_count: 0,
      incident_count: 0,
      entities_at_risk: 0,
      flagged_events: 0,
      benign_events: 42,
    },
    overview: {
      total_events: 42,
      distinct: { source_ips: 2, destination_ips: 1, usernames: 0, domains: 0, services: 1 },
      protocol: {},
      status: {},
      top_services: [],
      top_source_ips: [],
      top_destination_ips: [],
      top_usernames: [],
      top_domains: [],
      top_dstports: [],
      daily_volume: [],
      bytes: { sent: 0, received: 0 },
      flagged_events: 0,
      benign_events: 42,
      flagged_pct: 0,
    },
    categories: [],
    incidents: [],
    entity_risk: [],
    alerts: [],
    coverage: { rules_enabled: 12, scope: 'network and authentication behaviours' },
    not_detected: [],
    validation: null,
  }
}
