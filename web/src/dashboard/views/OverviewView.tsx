import type { Alert, EntityRisk, Incident, Report, Severity } from '../../report'
import { Chip, SEVERITY_ORDER, fmt, sevColor } from '../../ui'
import { Donut, VolumeChart } from '../../Charts'
import type { DashboardAction, DashboardFilters } from '../dashboardState'

function ViewHead({ title, copy }: { title: string; copy: string }) {
  return (
    <div className="view-head">
      <div><span className="view-index">01 / Snapshot</span><h1>{title}</h1></div>
      <p>{copy}</p>
    </div>
  )
}

function SeverityDonut({
  report,
  selected,
  dispatch,
}: {
  report: Report
  selected: Severity | null
  dispatch: React.Dispatch<DashboardAction>
}) {
  const segments = SEVERITY_ORDER
    .map((severity) => ({
      key: severity,
      label: severity.toLowerCase(),
      value: report.summary.by_severity[severity] ?? 0,
      color: sevColor(severity as Severity),
    }))
    .filter((segment) => segment.value > 0)

  if (!segments.length) return <div className="empty-state">No alert severity data.</div>

  return (
    <Donut
      label="Alert severity distribution"
      segments={segments}
      centerValue={fmt(report.summary.alert_count)}
      centerLabel="alerts"
      selected={selected}
      onSelect={(key) => dispatch({ type: 'drill', filters: { severity: key as Severity } })}
    />
  )
}

export default function OverviewView({
  report,
  drill,
  alerts,
  incidents,
  entities,
  dispatch,
}: {
  report: Report
  drill: Partial<DashboardFilters> | null
  alerts: Alert[]
  incidents: Incident[]
  entities: EntityRisk[]
  dispatch: React.Dispatch<DashboardAction>
}) {
  const { summary, input } = report
  const topIncident = incidents[0] ?? report.incidents[0]
  const categories = [...report.categories].sort((a, b) => b.alerts - a.alerts || a.rule_id - b.rule_id)
  const maxCategory = Math.max(1, ...categories.map((category) => category.alerts))

  return (
    <div>
      <ViewHead
        title="Security snapshot"
        copy="One completed local analysis. Read the funnel left to right, then click any chart to open the alerts behind it."
      />

      <section className="funnel-grid" aria-label="Analysis funnel">
        <article className="funnel-card">
          <span>Unique matched events</span>
          <strong className="num">{fmt(summary.flagged_events)}</strong>
          <small>of {fmt(input.rows)} input rows</small>
        </article>
        <div className="funnel-arrow" aria-hidden="true">→</div>
        <article className="funnel-card">
          <span>Aggregated alerts</span>
          <strong className="num">{fmt(summary.alert_count)}</strong>
          <small>{fmt(alerts.length)} match active filters</small>
        </article>
        <div className="funnel-arrow" aria-hidden="true">→</div>
        <article className="funnel-card">
          <span>Grouped incidents</span>
          <strong className="num">{fmt(summary.incident_count)}</strong>
          <small>{fmt(incidents.length)} match active filters</small>
        </article>
      </section>

      {topIncident && (
        <button
          className="priority-strip"
          onClick={() => {
            dispatch({ type: 'navigate', view: 'investigate' })
            dispatch({ type: 'select_incident', id: topIncident.id })
          }}
        >
          <span className="priority-label">Highest priority</span>
          <Chip severity={topIncident.severity} small />
          <b>{topIncident.title}</b>
          <span className="mono-value">{topIncident.primary_entity}</span>
          <strong className="num">{topIncident.risk_score}/100</strong>
        </button>
      )}

      <section className="overview-grid">
        <article className="panel panel-wide">
          <div className="panel-title">
            <div><span>Whole file</span><h2>Input volume</h2></div>
            <p>All ingested events. Detection filters do not change this chart.</p>
          </div>
          <VolumeChart data={report.overview.daily_volume} />
        </article>

        <article className="panel">
          <div className="panel-title">
            <div><span>Detection</span><h2>Alert severity</h2></div>
            <p>Click a band to open those alerts without leaving this page.</p>
          </div>
          <SeverityDonut
            report={report}
            selected={(drill?.severity ?? null) === 'all' ? null : (drill?.severity as Severity | undefined) ?? null}
            dispatch={dispatch}
          />
        </article>

        <article className="panel">
          <div className="panel-title">
            <div><span>Detection</span><h2>Matched rules</h2></div>
            <p>Alert totals. Rule event totals can overlap.</p>
          </div>
          <div className="rule-bars">
            {categories.length === 0 && <div className="empty-state">No matched rule categories.</div>}
            {categories.slice(0, 8).map((category) => (
              <button
                key={category.rule_id}
                className={drill?.ruleId === category.rule_id ? 'rule-bar selected' : 'rule-bar'}
                onClick={() => dispatch({ type: 'drill', filters: { ruleId: category.rule_id } })}
                aria-pressed={drill?.ruleId === category.rule_id}
                aria-label={`${category.category.replace(/_/g, ' ')} rule ${category.rule_id}, ${category.alerts} alerts`}
              >
                <span><b>{category.category.replace(/_/g, ' ')}</b><small className="num">rule {category.rule_id}</small></span>
                <span className="rule-track"><span style={{ width: `${(category.alerts / maxCategory) * 100}%` }} /></span>
                <strong className="num">{fmt(category.alerts)}</strong>
              </button>
            ))}
          </div>
        </article>

        <article className="panel">
          <div className="panel-title">
            <div><span>Triage</span><h2>Priority incidents</h2></div>
            <button onClick={() => dispatch({ type: 'navigate', view: 'investigate' })}>View all</button>
          </div>
          <div className="compact-list">
            {incidents.slice(0, 5).map((incident) => (
              <button
                key={incident.id}
                onClick={() => {
                  dispatch({ type: 'navigate', view: 'investigate' })
                  dispatch({ type: 'select_incident', id: incident.id })
                }}
              >
                <span className="list-rank num">{incident.id.replace('INC-', '')}</span>
                <span><b>{incident.title}</b><small className="mono-value">{incident.primary_entity}</small></span>
                <Chip severity={incident.severity} small />
                <strong className="num">{incident.risk_score}</strong>
              </button>
            ))}
            {incidents.length === 0 && <div className="empty-state">No incident matches the active filters.</div>}
          </div>
        </article>

        <article className="panel">
          <div className="panel-title">
            <div><span>Risk</span><h2>Primary alert entities</h2></div>
            <button onClick={() => dispatch({ type: 'navigate', view: 'investigate' })}>View all</button>
          </div>
          <div className="entity-list">
            {entities.slice(0, 6).map((entity, index) => (
              <button
                key={entity.entity}
                onClick={() => dispatch({ type: 'drill', filters: { entity: entity.entity } })}
                aria-label={`Open alerts for ${entity.entity}`}
              >
                <span className="list-rank num">{String(index + 1).padStart(2, '0')}</span>
                <span className="mono-value">{entity.entity}</span>
                <span>{entity.alert_count} alerts</span>
                <strong className="num" style={{ color: sevColor(entity.severity) }}>{entity.risk_score}/100</strong>
              </button>
            ))}
            {entities.length === 0 && <div className="empty-state">No entity matches the active filters.</div>}
          </div>
        </article>

        <article className="panel trust-card">
          <div className="panel-title">
            <div><span>Trust</span><h2>Can this result be scored?</h2></div>
            <button onClick={() => dispatch({ type: 'navigate', view: 'trust' })}>Inspect</button>
          </div>
          <div className="trust-facts">
            <div><span>Schema</span><b>{input.schema}</b></div>
            <div><span>Malformed rows</span><b className="num">{fmt(input.malformed)}</b></div>
            <div><span>Label state</span><b>{report.validation?.label_audit.quality.replace(/_/g, ' ') ?? 'no labels'}</b></div>
          </div>
        </article>
      </section>
    </div>
  )
}
