import { AnimatePresence, motion } from 'framer-motion'
import { useMemo } from 'react'
import type { Report, Severity } from '../report'
import { fmt } from '../ui'
import type { DashboardAction, DashboardState } from './dashboardState'

const SEVERITIES: Array<Severity | 'all'> = ['all', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']

export default function FilterToolbar({
  report,
  state,
  dispatch,
  matchingAlerts,
}: {
  report: Report
  state: DashboardState
  dispatch: React.Dispatch<DashboardAction>
  matchingAlerts: number
}) {
  const rules = useMemo(
    () => [...new Set(report.alerts.map((alert) => alert.rule.id))].sort((a, b) => a - b),
    [report.alerts],
  )
  const entities = useMemo(
    () => [...new Set(report.alerts.map((alert) => alert.entity))].sort((a, b) => a.localeCompare(b)),
    [report.alerts],
  )
  const techniques = useMemo(
    () => [...new Set(report.alerts.flatMap((alert) => alert.rule.mitre.id))].sort(),
    [report.alerts],
  )
  const { filters } = state

  if (state.view === 'trust') {
    return (
      <div className="filter-scope-note" role="note">
        <span className="scope-mark" aria-hidden="true" />
        Whole-file trust view. Detection filters do not alter these metrics.
      </div>
    )
  }

  const chips: Array<{ key: string; label: string; clear: () => void }> = []
  if (filters.query) chips.push({
    key: 'query',
    label: `search: ${filters.query}`,
    clear: () => dispatch({ type: 'set_filter', key: 'query', value: '' }),
  })
  if (filters.severity !== 'all') chips.push({
    key: 'severity',
    label: `alert severity: ${filters.severity}`,
    clear: () => dispatch({ type: 'set_filter', key: 'severity', value: 'all' }),
  })
  if (filters.ruleId !== null) chips.push({
    key: 'rule',
    label: `rule: ${filters.ruleId}`,
    clear: () => dispatch({ type: 'set_filter', key: 'ruleId', value: null }),
  })
  if (filters.entity !== null) chips.push({
    key: 'entity',
    label: `primary entity: ${filters.entity}`,
    clear: () => dispatch({ type: 'set_filter', key: 'entity', value: null }),
  })
  if (filters.technique !== null) chips.push({
    key: 'technique',
    label: `technique: ${filters.technique}`,
    clear: () => dispatch({ type: 'set_filter', key: 'technique', value: null }),
  })

  return (
    <section className="filter-toolbar" aria-label="Detection filters">
      <div className="filter-controls">
        <label className="search-control">
          <span className="sr-only">Search findings</span>
          <input
            value={filters.query}
            onChange={(event) => dispatch({ type: 'set_filter', key: 'query', value: event.target.value })}
            placeholder="Search findings, rules, entities..."
          />
        </label>

        <label className="filter-control">
          <span>Alert severity</span>
          <select
            value={filters.severity}
            onChange={(event) => dispatch({
              type: 'set_filter',
              key: 'severity',
              value: event.target.value as Severity | 'all',
            })}
          >
            {SEVERITIES.map((severity) => <option key={severity} value={severity}>{severity}</option>)}
          </select>
        </label>

        <label className="filter-control">
          <span>Rule</span>
          <select
            value={filters.ruleId ?? ''}
            onChange={(event) => dispatch({
              type: 'set_filter',
              key: 'ruleId',
              value: event.target.value ? Number(event.target.value) : null,
            })}
          >
            <option value="">all</option>
            {rules.map((rule) => <option key={rule} value={rule}>{rule}</option>)}
          </select>
        </label>

        <label className="filter-control entity-control">
          <span>Primary entity</span>
          <input
            list="eventiq-entities"
            value={filters.entity ?? ''}
            onChange={(event) => dispatch({
              type: 'set_filter',
              key: 'entity',
              value: event.target.value || null,
            })}
            placeholder="all"
          />
          <datalist id="eventiq-entities">
            {entities.map((entity) => <option key={entity} value={entity} />)}
          </datalist>
        </label>

        <label className="filter-control">
          <span>Technique</span>
          <select
            value={filters.technique ?? ''}
            onChange={(event) => dispatch({
              type: 'set_filter',
              key: 'technique',
              value: event.target.value || null,
            })}
          >
            <option value="">all</option>
            {techniques.map((technique) => <option key={technique} value={technique}>{technique}</option>)}
          </select>
        </label>
      </div>

      <div className="filter-status">
        <div className="filter-chips" aria-label="Active filters">
          <AnimatePresence initial={false}>
            {chips.map((chip) => (
              <motion.button
                layout
                key={chip.key}
                className="filter-chip"
                onClick={chip.clear}
                initial={{ opacity: 0, y: -4 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -4 }}
                transition={{ duration: 0.16 }}
                aria-label={`Remove ${chip.label} filter`}
              >
                {chip.label}<span aria-hidden="true"> ×</span>
              </motion.button>
            ))}
          </AnimatePresence>
          {chips.length === 0 && <span className="filter-empty">No detection filters active</span>}
        </div>
        <div className="filter-count" aria-live="polite">
          <b className="num">{fmt(matchingAlerts)}</b> of <span className="num">{fmt(report.alerts.length)}</span> alerts
          {chips.length > 0 && (
            <button className="reset-filters" onClick={() => dispatch({ type: 'reset_filters' })}>Reset</button>
          )}
        </div>
      </div>
    </section>
  )
}
