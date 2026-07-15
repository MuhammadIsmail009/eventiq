import { AnimatePresence, motion } from 'framer-motion'
import { useCallback, useRef } from 'react'
import type { EntityRisk, Incident, Report } from '../../report'
import { Chip, fmt, sevColor } from '../../ui'
import type { DashboardAction, DashboardFilters, DashboardState } from '../dashboardState'
import { selectRelatedAlerts } from '../dashboardState'
import { IncidentDetails } from '../InvestigationPanel'
import { TACTIC_ORDER, techniqueInfo } from '../techniques'

/**
 * One investigation workspace.
 *
 * Incidents, the entities behind them, and the techniques they map to used to
 * be three separate destinations that all drilled into a fourth. They are one
 * screen now: pick an incident to read its evidence beside the list, or drill
 * any row to open the alerts underneath it in the drawer.
 */
export default function InvestigateView({
  report,
  incidents,
  entities,
  filters,
  state,
  dispatch,
}: {
  report: Report
  incidents: Incident[]
  entities: EntityRisk[]
  filters: DashboardFilters
  state: DashboardState
  dispatch: React.Dispatch<DashboardAction>
}) {
  const triggerRef = useRef<HTMLButtonElement | null>(null)
  const selected = incidents.find((item) => item.id === state.selectedIncidentId)

  const close = useCallback(() => {
    dispatch({ type: 'select_incident', id: null })
    requestAnimationFrame(() => triggerRef.current?.focus())
  }, [dispatch])

  const observed = [...new Set([
    ...report.categories.flatMap((category) => category.mitre),
    ...report.incidents.flatMap((incident) => incident.techniques),
  ])].sort()
  const groups = new Map<string, string[]>()
  for (const id of observed) {
    const tactic = techniqueInfo(id).tactic
    groups.set(tactic, [...(groups.get(tactic) ?? []), id])
  }
  const visibleEntities = entities.slice(0, 25)

  return (
    <div>
      <div className="view-head">
        <div><span className="view-index">02 / Investigate</span><h1>Incidents and evidence</h1></div>
        <p>Campaigns ranked by triage risk. Select one to read its evidence, or open the alerts underneath any row.</p>
      </div>

      <div className="master-detail">
        <section className="master-list" aria-label="Incident list">
          <div className="list-header">
            <span><b className="num">{fmt(incidents.length)}</b> matching incidents</span>
            <span>Risk ordered</span>
          </div>
          {incidents.length === 0 && <div className="empty-state large">No incident matches the active filters.</div>}
          {incidents.map((incident) => {
            const active = selected?.id === incident.id
            return (
              <motion.button
                layout
                key={incident.id}
                ref={active ? triggerRef : undefined}
                className={active ? 'incident-row selected' : 'incident-row'}
                onClick={(event) => {
                  triggerRef.current = event.currentTarget
                  dispatch({ type: 'select_incident', id: incident.id })
                }}
                aria-pressed={active}
                aria-label={`Open incident: ${incident.title} on ${incident.primary_entity}`}
              >
                <span className="incident-rank num">{incident.id}</span>
                <span className="incident-main">
                  <b>{incident.title}</b>
                  <small>{incident.category.replace(/_/g, ' ')}</small>
                </span>
                <Chip severity={incident.severity} small />
                <span className="mono-value incident-entity">{incident.primary_entity}</span>
                <span className="incident-counts">
                  <b className="num">{fmt(incident.alert_count)}</b> alerts
                  <small className="num">{fmt(incident.event_count)} matched events</small>
                </span>
                <strong className="incident-risk num">{incident.risk_score}</strong>
              </motion.button>
            )
          })}
        </section>

        <AnimatePresence mode="wait" initial={false}>
          {selected ? (
            <IncidentDetails
              key={selected.id}
              incident={selected}
              relatedAlertCount={selectRelatedAlerts(report, selected).length}
              onClose={close}
              onViewRelated={() => dispatch({ type: 'drill', filters: { ruleId: selected.rule_id } })}
            />
          ) : (
            <div className="detail-placeholder" role="note">
              Select an incident to inspect its evidence and related alerts.
            </div>
          )}
        </AnimatePresence>
      </div>

      <section className="entity-workspace">
        <article className="panel entity-ranking">
          <div className="panel-title">
            <div><span>Risk</span><h2>Entities behind these incidents</h2></div>
            <p>{fmt(entities.length)} match · top {fmt(visibleEntities.length)} shown</p>
          </div>
          <div className="entity-table-head" aria-hidden="true">
            <span>Rank</span><span>Entity</span><span>Risk band</span><span>Contributors</span><span>Score</span>
          </div>
          <div className="entity-table">
            {visibleEntities.map((entity, index) => (
              <motion.button
                layout
                key={entity.entity}
                onClick={() => dispatch({ type: 'drill', filters: { entity: entity.entity } })}
                aria-label={`Open alerts for ${entity.entity}`}
              >
                <span className="list-rank num">{String(index + 1).padStart(2, '0')}</span>
                <span className="mono-value">{entity.entity}</span>
                <Chip severity={entity.severity} small />
                <span className="entity-contributors">
                  <b className="num">{entity.alert_count}</b> alerts · rules {entity.contributing_rules.join(', ')}
                </span>
                <strong className="num" style={{ color: sevColor(entity.severity) }}>{entity.risk_score}/100</strong>
              </motion.button>
            ))}
            {entities.length === 0 && <div className="empty-state large">No entity matches the active detection filters.</div>}
          </div>
          <p className="scope-copy">Risk is a relative triage score, not a probability of compromise. Filtering changes membership, never the stored score.</p>
        </article>

        <article className="panel attack-panel">
          <div className="panel-title">
            <div><span>Evidence mapping</span><h2>Observed MITRE ATT&amp;CK</h2></div>
            <p>{fmt(observed.length)} techniques attached to matched rules</p>
          </div>
          <div className="tactic-groups">
            {TACTIC_ORDER.filter((tactic) => groups.has(tactic)).map((tactic) => (
              <section key={tactic}>
                <h3>{tactic}</h3>
                <div>
                  {groups.get(tactic)!.map((id) => {
                    const info = techniqueInfo(id)
                    const active = filters.technique === id
                    return (
                      <button
                        key={id}
                        className={active ? 'technique-button selected' : 'technique-button'}
                        onClick={() => dispatch({ type: 'drill', filters: { technique: active ? null : id } })}
                        aria-pressed={active}
                      >
                        <b className="num">{id}</b><span>{info.name}</span>
                      </button>
                    )
                  })}
                </div>
              </section>
            ))}
            {observed.length === 0 && <div className="empty-state">No ATT&amp;CK mappings were observed.</div>}
          </div>
          <div className="scope-box">
            <b>Boundary</b>
            <p>Only mappings attached to rules that matched this snapshot are shown. Empty tactics do not mean they were tested. This is not full framework coverage.</p>
          </div>
        </article>
      </section>
    </div>
  )
}
