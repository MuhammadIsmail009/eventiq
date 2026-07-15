import { describe, expect, it } from 'vitest'
import type { Alert, EntityRisk, Incident, Report } from '../report'
import { makeReport } from '../test/reportFixture'
import {
  DEFAULT_FILTERS,
  FILTER_SCOPE,
  createInitialDashboardState,
  dashboardReducer,
  selectFilteredAlerts,
  selectFilteredEntities,
  selectFilteredIncidents,
  selectMatchingPrimaryEntityCount,
  selectRelatedAlerts,
  selectWholeFileData,
} from './dashboardState'

function alert(
  ruleId: number,
  severity: Alert['severity'],
  entity: string,
  technique: string,
  risk: number,
  firstSeen: string,
): Alert {
  return {
    rule: {
      id: ruleId,
      level: severity === 'CRITICAL' ? 14 : severity === 'HIGH' ? 12 : 8,
      description: `Rule ${ruleId} detector`,
      mitre: { id: [technique] },
    },
    title: `Finding ${ruleId} on ${entity}`,
    severity,
    risk_score: risk,
    entity,
    first_seen: firstSeen,
    last_seen: firstSeen,
    data: {},
    evidence: { events: 5 },
    sample_rows: [],
    status: 'open',
  }
}

function incident(
  id: string,
  ruleId: number,
  severity: Incident['severity'],
  entity: string,
  technique: string,
): Incident {
  return {
    id,
    rule_id: ruleId,
    title: `Campaign ${ruleId}`,
    category: ruleId === 100100 ? 'authentication' : 'execution',
    basis: 'report-backed evidence',
    primary_entity: entity,
    severity,
    risk_score: severity === 'CRITICAL' ? 95 : 80,
    techniques: [technique],
    first_seen: '2026-07-01 00:00:00',
    last_seen: '2026-07-01 00:10:00',
    alert_count: 2,
    event_count: 10,
    affected_count: 2,
    affected_entities: [entity, ruleId === 100100 ? 'secondary' : 'other'],
    narrative: 'A grouped detection campaign.',
  }
}

function entity(
  value: string,
  severity: EntityRisk['severity'],
  rules: number[],
  techniques: string[],
): EntityRisk {
  return {
    entity: value,
    risk_score: severity === 'CRITICAL' ? 95 : 70,
    severity,
    contributing_rules: rules,
    techniques,
    alert_count: rules.length,
  }
}

function populatedReport(): Report {
  const report = makeReport()
  report.alerts = [
    alert(100100, 'HIGH', '10.10.20.15', 'T1110.003', 80, '2026-07-01 00:02:00'),
    alert(100200, 'CRITICAL', '192.168.10.83', 'T1059.001', 95, '2026-07-01 00:03:00'),
    alert(100100, 'HIGH', 'secondary', 'T1110.003', 80, '2026-07-01 00:01:00'),
  ]
  report.incidents = [
    incident('INC-0001', 100200, 'CRITICAL', '192.168.10.83', 'T1059.001'),
    incident('INC-0002', 100100, 'HIGH', '10.10.20.15', 'T1110.003'),
  ]
  report.entity_risk = [
    entity('192.168.10.83', 'CRITICAL', [100200], ['T1059.001']),
    entity('10.10.20.15', 'HIGH', [100100], ['T1110.003']),
  ]
  report.summary.alert_count = report.alerts.length
  report.summary.incident_count = report.incidents.length
  report.summary.entities_at_risk = report.entity_risk.length
  return report
}

describe('dashboard reducer', () => {
  it('drills into alerts without leaving the workspace it drilled from', () => {
    const initial = createInitialDashboardState()
    const drilled = dashboardReducer(initial, {
      type: 'drill',
      filters: { ruleId: 100100, severity: 'HIGH' },
    })
    // The point of the drawer: the view underneath never changes.
    expect(drilled.view).toBe('overview')
    expect(drilled.drill).toEqual({ ruleId: 100100, severity: 'HIGH' })
    // The drill scope must stay off the workspace filters, or closing the
    // drawer would leave the page filtered by a passing glance.
    expect(drilled.filters).toEqual(DEFAULT_FILTERS)

    const reset = dashboardReducer(drilled, { type: 'reset_filters' })
    expect(reset.view).toBe('overview')
    expect(reset.filters).toEqual(DEFAULT_FILTERS)
    expect(reset.visibleAlertLimit).toBe(40)
  })

  it('closes the drawer without discarding the workspace or its selection', () => {
    const investigating = dashboardReducer(
      dashboardReducer(createInitialDashboardState(), { type: 'navigate', view: 'investigate' }),
      { type: 'select_incident', id: 'INC-0001' },
    )
    const drilled = dashboardReducer(investigating, { type: 'drill', filters: { ruleId: 100100 } })
    const closed = dashboardReducer(drilled, { type: 'close_drill' })

    expect(closed.drill).toBeNull()
    expect(closed.view).toBe('investigate')
    // Closing the drill returns to the incident that opened it, not to a
    // blank list.
    expect(closed.selectedIncidentId).toBe('INC-0001')
  })

  it('closes the drawer when the reviewer changes workspace', () => {
    const drilled = dashboardReducer(createInitialDashboardState(), {
      type: 'drill',
      filters: { severity: 'HIGH' },
    })
    const moved = dashboardReducer(drilled, { type: 'navigate', view: 'trust' })
    expect(moved.drill).toBeNull()
    expect(moved.selectedAlertKey).toBeNull()
  })

  it('resets the visible alert limit when a filter changes', () => {
    const expanded = dashboardReducer(createInitialDashboardState(), { type: 'show_more_alerts' })
    expect(expanded.visibleAlertLimit).toBe(100)
    const filtered = dashboardReducer(expanded, { type: 'set_filter', key: 'query', value: 'dns' })
    expect(filtered.visibleAlertLimit).toBe(40)
  })
})

describe('dashboard selectors', () => {
  it('supports each honest alert filter and combined filtering', () => {
    const report = populatedReport()
    expect(selectFilteredAlerts(report, { ...DEFAULT_FILTERS, severity: 'CRITICAL' }, 'risk')).toHaveLength(1)
    expect(selectFilteredAlerts(report, { ...DEFAULT_FILTERS, ruleId: 100100 }, 'risk')).toHaveLength(2)
    expect(selectFilteredAlerts(report, { ...DEFAULT_FILTERS, entity: 'secondary' }, 'risk')).toHaveLength(1)
    expect(selectFilteredAlerts(report, { ...DEFAULT_FILTERS, technique: 'T1110.003' }, 'risk')).toHaveLength(2)
    expect(selectFilteredAlerts(report, { ...DEFAULT_FILTERS, query: 'detector' }, 'risk')).toHaveLength(3)

    const combined = {
      ...DEFAULT_FILTERS,
      severity: 'HIGH' as const,
      ruleId: 100100,
      entity: '10.10.20.15',
    }
    expect(selectFilteredAlerts(report, combined, 'risk').map((item) => item.entity)).toEqual(['10.10.20.15'])
  })

  it('sorts deterministically without mutating report alerts', () => {
    const report = populatedReport()
    const rows = selectFilteredAlerts(report, DEFAULT_FILTERS, 'risk')
    expect(rows.map((item) => `${item.risk_score}:${item.rule.id}:${item.entity}`)).toEqual([
      '95:100200:192.168.10.83',
      '80:100100:10.10.20.15',
      '80:100100:secondary',
    ])
    expect(report.alerts[0]?.entity).toBe('10.10.20.15')
  })

  it('filters incidents only on fields the report proves', () => {
    const report = populatedReport()
    expect(selectFilteredIncidents(report, { ...DEFAULT_FILTERS, ruleId: 100100 })).toHaveLength(1)
    expect(selectFilteredIncidents(report, { ...DEFAULT_FILTERS, entity: 'secondary' })).toHaveLength(1)
    expect(selectFilteredIncidents(report, { ...DEFAULT_FILTERS, technique: 'T1059.001' })[0]?.id).toBe('INC-0001')
  })

  it('finds incident entities from alerts even when the display list is capped', () => {
    const report = populatedReport()
    report.alerts.push(alert(100100, 'HIGH', 'outside-display-cap', 'T1110.003', 70, '2026-07-01 00:04:00'))
    expect(report.incidents[1]?.affected_entities).not.toContain('outside-display-cap')
    expect(selectFilteredIncidents(report, { ...DEFAULT_FILTERS, entity: 'outside-display-cap' })[0]?.id).toBe('INC-0002')
  })

  it('filters entity risk without inventing types or recalculating risk', () => {
    const report = populatedReport()
    const rows = selectFilteredEntities(report, { ...DEFAULT_FILTERS, ruleId: 100100 })
    expect(rows.map((item) => item.entity)).toEqual(['10.10.20.15'])
    expect(rows[0]?.risk_score).toBe(70)
  })

  it('keeps global severity as alert severity instead of entity risk band', () => {
    const report = populatedReport()
    const target = report.entity_risk.find((item) => item.entity === '10.10.20.15')!
    target.severity = 'CRITICAL'
    target.risk_score = 95

    const high = selectFilteredEntities(report, { ...DEFAULT_FILTERS, severity: 'HIGH' })
    const critical = selectFilteredEntities(report, { ...DEFAULT_FILTERS, severity: 'CRITICAL' })
    expect(high.map((item) => item.entity)).toContain('10.10.20.15')
    expect(critical.map((item) => item.entity)).not.toContain('10.10.20.15')
  })

  it('requires combined detection filters to match the same alert', () => {
    const report = populatedReport()
    const rows = selectFilteredEntities(report, {
      ...DEFAULT_FILTERS,
      severity: 'HIGH',
      ruleId: 100200,
    })
    expect(rows).toEqual([])
  })

  it('uses explicit incident rule ids for exact related alerts', () => {
    const report = populatedReport()
    const related = selectRelatedAlerts(report, report.incidents[1]!)
    expect(related).toHaveLength(2)
    expect(related.every((item) => item.rule.id === 100100)).toBe(true)
  })

  it('counts matching primary alert entities, not affected or matched events', () => {
    const report = populatedReport()
    const alerts = selectFilteredAlerts(report, { ...DEFAULT_FILTERS, ruleId: 100100 }, 'risk')
    expect(selectMatchingPrimaryEntityCount(alerts)).toBe(2)
  })

  it('keeps whole-file data outside detection filter ownership', () => {
    const report = populatedReport()
    const wholeFile = selectWholeFileData(report)
    expect(FILTER_SCOPE.wholeFile).toEqual([])
    expect(wholeFile.overview).toBe(report.overview)
    expect(wholeFile.input.rows).toBe(42)
    expect(wholeFile.summary.flagged_events).toBe(0)
  })
})
