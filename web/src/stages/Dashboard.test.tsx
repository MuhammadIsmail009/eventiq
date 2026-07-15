import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import type { Alert, Incident, Report, Validation } from '../report'
import { makeReport } from '../test/reportFixture'
import Dashboard from './Dashboard'

const unsupportedValidation: Validation = {
  label_audit: { quality: 'unsupported', scored_rules: 0, known_campaigns_present: [], distinct_labels: 3 },
  per_rule: {},
  overall: null,
  naive_failed_login_baseline: { precision: null, note: 'Nothing scorable.' },
  unscored: [],
}

const scoredValidation: Validation = {
  label_audit: { quality: 'fully_scorable', scored_rules: 1, known_campaigns_present: ['FAILED_LOGIN_BURST'], distinct_labels: 2 },
  per_rule: {
    brute_force: {
      rule_id: 100100,
      campaign: 'FAILED_LOGIN_BURST',
      tp: 10,
      fp: 0,
      fn: 0,
      precision: 1,
      recall: 1,
      f1: 1,
      alerts: 1,
      alerts_valid: 1,
    },
  },
  overall: { tp: 10, fp: 0, fn: 0, precision: 1, recall: 1, f1: 1 },
  naive_failed_login_baseline: { precision: 0.463, note: 'Naive baseline.' },
  unscored: [{ rule_id: 100200, note: 'No supported label.', alerts: 1 }],
}

function alert(ruleId: number, title: string, severity: Alert['severity'], entity: string, technique: string): Alert {
  return {
    rule: { id: ruleId, level: severity === 'CRITICAL' ? 14 : 12, description: `${title} rule evidence`, mitre: { id: [technique] } },
    title,
    severity,
    risk_score: severity === 'CRITICAL' ? 95 : 80,
    entity,
    first_seen: '2026-07-15 00:01:00',
    last_seen: '2026-07-15 00:05:00',
    data: { destination: entity },
    evidence: { events: 20, distinct_sources: 60 },
    sample_rows: ['L0001', 'L0002'],
    status: 'open',
  }
}

function incident(ruleId: number, id: string, title: string, severity: Incident['severity'], entity: string, technique: string): Incident {
  return {
    id,
    rule_id: ruleId,
    title,
    category: ruleId === 100100 ? 'classic_brute_force' : 'powershell_execution',
    basis: 'destination aggregate',
    primary_entity: entity,
    severity,
    risk_score: severity === 'CRITICAL' ? 95 : 80,
    techniques: [technique],
    first_seen: '2026-07-15 00:01:00',
    last_seen: '2026-07-15 00:05:00',
    alert_count: 1,
    event_count: 20,
    affected_count: 1,
    affected_entities: [entity],
    narrative: 'A grouped detection campaign.',
  }
}

function makeDashboardReport(): Report {
  const report = makeReport()
  report.input.rows = 61
  report.summary = {
    by_severity: { HIGH: 1, CRITICAL: 1 },
    distinct_rules: [100100, 100200],
    alert_count: 2,
    incident_count: 2,
    entities_at_risk: 2,
    flagged_events: 20,
    benign_events: 41,
  }
  report.overview.daily_volume = [['2026-07-15', 61]]
  report.alerts = [
    alert(100100, 'Failed authentication campaign', 'HIGH', '10.10.20.15', 'T1110.003'),
    alert(100200, 'PowerShell execution', 'CRITICAL', '192.168.10.83', 'T1059.001'),
  ]
  report.incidents = [
    incident(100200, 'INC-0001', 'PowerShell execution', 'CRITICAL', '192.168.10.83', 'T1059.001'),
    incident(100100, 'INC-0002', 'Failed authentication campaign', 'HIGH', '10.10.20.15', 'T1110.003'),
  ]
  report.categories = [
    { rule_id: 100100, category: 'classic_brute_force', basis: 'destination aggregate', severity: 'HIGH', events: 20, alerts: 1, mitre: ['T1110.003'] },
    { rule_id: 100200, category: 'powershell_execution', basis: 'command evidence', severity: 'CRITICAL', events: 1, alerts: 1, mitre: ['T1059.001'] },
  ]
  report.entity_risk = [
    { entity: '192.168.10.83', risk_score: 95, severity: 'CRITICAL', contributing_rules: [100200], techniques: ['T1059.001'], alert_count: 1 },
    { entity: '10.10.20.15', risk_score: 80, severity: 'HIGH', contributing_rules: [100100], techniques: ['T1110.003'], alert_count: 1 },
  ]
  return report
}

async function openWorkspace(name: RegExp) {
  fireEvent.click(screen.getByRole('button', { name }))
}

describe('operational dashboard', () => {
  it('opens on an honest snapshot funnel instead of a report chapter', () => {
    render(<Dashboard report={makeDashboardReport()} onReset={vi.fn()} />)
    expect(screen.getByText('snapshot analysis')).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: 'Security snapshot' })).toBeInTheDocument()
    expect(screen.getByText('Unique matched events')).toBeInTheDocument()
    expect(screen.getByText('Aggregated alerts')).toBeInTheDocument()
    expect(screen.getByText('Grouped incidents')).toBeInTheDocument()
    expect(screen.getByText(/Local · read only/i)).toBeInTheDocument()
  })

  it('keeps no-label and unsupported-label states honest in Trust + Data', async () => {
    const report = makeDashboardReport()
    const { rerender } = render(<Dashboard report={report} onReset={vi.fn()} />)
    await openWorkspace(/Trust \+ Data/)
    expect(await screen.findByRole('heading', { name: 'Accuracy check unavailable' })).toBeInTheDocument()
    expect(screen.getByText(/no supported label column/i)).toBeInTheDocument()

    report.validation = unsupportedValidation
    rerender(<Dashboard report={report} onReset={vi.fn()} />)
    await openWorkspace(/Trust \+ Data/)
    expect(await screen.findByText(/none name a campaign/i)).toBeInTheDocument()
    const labels = screen.getByText('Distinct labels').parentElement
    expect(labels).not.toBeNull()
    expect(within(labels!).getByText('3')).toBeInTheDocument()
  })

  it('shows held-out validation scores and the fractional baseline', async () => {
    const report = makeDashboardReport()
    report.validation = scoredValidation
    render(<Dashboard report={report} onReset={vi.fn()} />)
    await openWorkspace(/Trust \+ Data/)
    expect(await screen.findByRole('heading', { name: 'Does it actually work?' })).toBeInTheDocument()
    expect(screen.getAllByText('1.000').length).toBeGreaterThanOrEqual(3)
    expect(screen.getByText('0.463')).toBeInTheDocument()
    expect(screen.getByText(/No supported label/i)).toBeInTheDocument()
  })

  it('filters the drilled alerts by detection severity and exposes a removable chip', async () => {
    render(<Dashboard report={makeDashboardReport()} onReset={vi.fn()} />)
    fireEvent.change(screen.getByLabelText('Alert severity'), { target: { value: 'CRITICAL' } })
    fireEvent.click(screen.getByRole('button', { name: /^critical: 1, /i }))
    const drawer = await screen.findByRole('complementary', { name: 'Matching alerts' })
    expect(within(drawer).getByText('PowerShell execution')).toBeInTheDocument()
    expect(within(drawer).queryByText('Failed authentication campaign')).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: /Remove alert severity: CRITICAL filter/i })).toBeInTheDocument()
  })

  it('opens the severity donut into a drawer without leaving the overview', async () => {
    render(<Dashboard report={makeDashboardReport()} onReset={vi.fn()} />)
    // The legend row is the keyboard path into the ring, so it is what a
    // reviewer tabbing the demo would actually hit.
    fireEvent.click(screen.getByRole('button', { name: /^critical: 1, /i }))
    const drawer = await screen.findByRole('complementary', { name: 'Matching alerts' })
    expect(within(drawer).getByText('PowerShell execution')).toBeInTheDocument()
    expect(within(drawer).queryByText('Failed authentication campaign')).not.toBeInTheDocument()
    // The workspace underneath must survive the drill. This is the whole fix:
    // the reviewer never gets teleported to a separate alerts page.
    expect(screen.getByRole('heading', { name: 'Security snapshot' })).toBeInTheDocument()
    // The drill scope belongs to the drawer, not the toolbar: closing it must
    // not leave the overview quietly filtered.
    expect(within(drawer).getByRole('heading', { name: /critical severity/i })).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /Remove alert severity/i })).not.toBeInTheDocument()
  })

  it('names the drilled scope so two drills never look like the same screen', async () => {
    render(<Dashboard report={makeDashboardReport()} onReset={vi.fn()} />)
    fireEvent.click(screen.getByRole('button', { name: /^critical: 1, /i }))
    const bySeverity = await screen.findByRole('complementary', { name: 'Matching alerts' })
    expect(within(bySeverity).getByRole('heading', { name: /critical severity/i })).toBeInTheDocument()

    fireEvent.click(within(bySeverity).getByRole('button', { name: 'Close matching alerts' }))
    await waitFor(() => expect(screen.queryByRole('complementary', { name: 'Matching alerts' })).not.toBeInTheDocument())

    fireEvent.click(screen.getByRole('button', { name: /Open alerts for 10\.10\.20\.15/i }))
    const byEntity = await screen.findByRole('complementary', { name: 'Matching alerts' })
    expect(within(byEntity).getByRole('heading', { name: /10\.10\.20\.15/ })).toBeInTheDocument()
  })

  it('states every donut number in the legend rather than only in the ring', () => {
    render(<Dashboard report={makeDashboardReport()} onReset={vi.fn()} />)
    // Colour alone must never carry a value: each arc has a labelled count.
    const critical = screen.getByRole('button', { name: /^critical: 1, /i })
    expect(critical).toHaveTextContent('critical')
    expect(critical).toHaveTextContent('1')
  })

  it('drills a rule chart into the alerts behind that bar', async () => {
    render(<Dashboard report={makeDashboardReport()} onReset={vi.fn()} />)
    fireEvent.click(screen.getByRole('button', { name: /classic brute force rule 100100/i }))
    const drawer = await screen.findByRole('complementary', { name: 'Matching alerts' })
    expect(within(drawer).getByText('Failed authentication campaign')).toBeInTheDocument()
    expect(within(drawer).queryByText('PowerShell execution')).not.toBeInTheDocument()
    expect(within(drawer).getByRole('heading', { name: /classic brute force/i })).toBeInTheDocument()
  })

  it('steps Escape back through evidence to the list, then closes and returns focus', async () => {
    render(<Dashboard report={makeDashboardReport()} onReset={vi.fn()} />)
    const trigger = screen.getByRole('button', { name: /classic brute force rule 100100/i })
    trigger.focus()
    fireEvent.click(trigger)

    const drawer = await screen.findByRole('complementary', { name: 'Matching alerts' })
    fireEvent.click(within(drawer).getByRole('button', { name: /Open alert: Failed authentication campaign/i }))
    expect(await screen.findByText('Why it fired')).toBeInTheDocument()

    // First Escape steps back to the list rather than throwing away the drill.
    fireEvent.keyDown(window, { key: 'Escape' })
    await waitFor(() => expect(screen.queryByText('Why it fired')).not.toBeInTheDocument())
    expect(screen.getByRole('complementary', { name: 'Matching alerts' })).toBeInTheDocument()

    // Second Escape closes the drawer and hands focus back to the bar.
    fireEvent.keyDown(window, { key: 'Escape' })
    await waitFor(() => expect(screen.queryByRole('complementary', { name: 'Matching alerts' })).not.toBeInTheDocument())
    await waitFor(() => expect(trigger).toHaveFocus())
  })

  it('uses the explicit incident rule relationship for related alerts', async () => {
    render(<Dashboard report={makeDashboardReport()} onReset={vi.fn()} />)
    await openWorkspace(/Investigate/)
    const incidentRow = await screen.findByRole('button', { name: /Open incident: Failed authentication campaign/i })
    fireEvent.click(incidentRow)
    fireEvent.click(await screen.findByRole('button', { name: /View 1 related alerts/i }))

    const drawer = await screen.findByRole('complementary', { name: 'Matching alerts' })
    expect(within(drawer).getByText('Failed authentication campaign')).toBeInTheDocument()
    expect(within(drawer).queryByText('PowerShell execution')).not.toBeInTheDocument()
    // The incident that launched the drill is still open behind the drawer.
    expect(screen.getByRole('complementary', { name: 'INC-0002 details' })).toBeInTheDocument()
  })

  it('discloses partial schema and missing optional fields', async () => {
    const report = makeDashboardReport()
    report.input.schema = 'partial'
    report.input.missing_optional = ['username', 'command']
    render(<Dashboard report={report} onReset={vi.fn()} />)
    expect(screen.getByText('partial schema')).toBeInTheDocument()
    await openWorkspace(/Trust \+ Data/)
    expect(await screen.findByText('username, command')).toBeInTheDocument()
  })

  it('renders entity risk and observed ATT&CK without claiming coverage', async () => {
    render(<Dashboard report={makeDashboardReport()} onReset={vi.fn()} />)
    await openWorkspace(/Investigate/)
    expect(await screen.findByRole('heading', { name: 'Incidents and evidence' })).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: 'Entities behind these incidents' })).toBeInTheDocument()
    expect(screen.getByText('Credential Access')).toBeInTheDocument()
    expect(screen.getByText(/not full framework coverage/i)).toBeInTheDocument()
  })

  it('presents exactly three workspaces so the demo has one path through', () => {
    render(<Dashboard report={makeDashboardReport()} onReset={vi.fn()} />)
    const nav = screen.getByRole('navigation', { name: 'Dashboard workspaces' })
    expect(within(nav).getAllByRole('button')).toHaveLength(3)
  })

  it('handles a zero-alert report without dead controls or invented risk', async () => {
    render(<Dashboard report={makeReport()} onReset={vi.fn()} />)
    expect(screen.getByText('No matched rule categories.')).toBeInTheDocument()
    await openWorkspace(/Investigate/)
    // Wait on the heading, not the empty-state text: the overview carries a
    // near-identical string and would resolve before the view swaps.
    expect(await screen.findByRole('heading', { name: 'Incidents and evidence' })).toBeInTheDocument()
    expect(screen.getByText('No incident matches the active filters.')).toBeInTheDocument()
    expect(screen.getByText('No entity matches the active detection filters.')).toBeInTheDocument()
  })
})
