import { AnimatePresence, motion } from 'framer-motion'
import { useCallback, useEffect, useRef } from 'react'
import type { Alert, Report } from '../report'
import { Chip, fmt, sevColor } from '../ui'
import type { AlertSort, DashboardAction, DashboardFilters, DashboardState } from './dashboardState'
import { alertKey, describeFilters } from './dashboardState'
import { AlertEvidence } from './InvestigationPanel'

/**
 * The one destination for every drill-down in the dashboard.
 *
 * Charts, entities, techniques and incidents all open this drawer over the
 * workspace that launched it. Nothing navigates, so closing the drawer always
 * returns the reviewer to the exact screen and scroll position they clicked
 * from. The drawer states its own scope in words for the same reason.
 */
export default function DrillDrawer({
  report,
  alerts,
  scopeFilters,
  state,
  dispatch,
}: {
  report: Report
  alerts: Alert[]
  scopeFilters: DashboardFilters
  state: DashboardState
  dispatch: React.Dispatch<DashboardAction>
}) {
  const open = state.drill !== null
  const selected = alerts.find((alert) => alertKey(alert) === state.selectedAlertKey)
  const visible = alerts.slice(0, state.visibleAlertLimit)
  const scope = describeFilters(scopeFilters, report)

  const close = useCallback(() => dispatch({ type: 'close_drill' }), [dispatch])
  const back = useCallback(() => dispatch({ type: 'select_alert', key: null }), [dispatch])

  // Remember whatever opened the drawer so closing it hands focus back to that
  // exact chart segment or row, rather than dumping the reviewer at the top of
  // the document.
  const opener = useRef<HTMLElement | null>(null)
  useEffect(() => {
    if (open) {
      opener.current = document.activeElement as HTMLElement | null
      return
    }
    const trigger = opener.current
    opener.current = null
    if (trigger?.isConnected) requestAnimationFrame(() => trigger.focus())
  }, [open])

  useEffect(() => {
    if (!open) return
    const onKey = (event: KeyboardEvent) => {
      if (event.key !== 'Escape') return
      // Escape steps back one level before it closes, so the key never loses
      // more context than the reviewer expects.
      if (state.selectedAlertKey) back()
      else close()
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [open, state.selectedAlertKey, back, close])

  return (
    <AnimatePresence>
      {open && (
        <>
          <motion.div
            className="drill-scrim"
            onClick={close}
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.16 }}
          />
          <motion.aside
            className="drill-drawer"
            role="complementary"
            aria-label="Matching alerts"
            initial={{ x: '100%' }}
            animate={{ x: 0 }}
            exit={{ x: '100%' }}
            transition={{ type: 'spring', stiffness: 380, damping: 40 }}
          >
            <div className="drill-head">
              <div>
                <span className="drill-eyebrow">Showing alerts for</span>
                <h3>{scope}</h3>
                <p className="drill-count">
                  <b className="num">{fmt(alerts.length)}</b> of {fmt(report.summary.alert_count)} alerts in the snapshot
                </p>
              </div>
              <button className="panel-close" onClick={close} aria-label="Close matching alerts">Close</button>
            </div>

            <div className="drill-body">
              {selected ? (
                <div className="drill-detail">
                  <button className="drill-back" onClick={back}>
                    Back to {fmt(alerts.length)} alerts
                  </button>
                  <AlertEvidence alert={selected} />
                </div>
              ) : (
                <>
                  <div className="drill-tools">
                    <label>
                      <span>Sort</span>
                      <select
                        value={state.alertSort}
                        onChange={(event) => dispatch({ type: 'set_alert_sort', sort: event.target.value as AlertSort })}
                      >
                        <option value="risk">risk</option>
                        <option value="recent">recent</option>
                        <option value="rule">rule</option>
                        <option value="severity">severity</option>
                      </select>
                    </label>
                  </div>

                  {alerts.length === 0 && (
                    <div className="empty-state large">No alert matches the active filters.</div>
                  )}

                  <div className="drill-list">
                    {visible.map((alert) => (
                      <button
                        key={alertKey(alert)}
                        className="drill-row"
                        onClick={() => dispatch({ type: 'select_alert', key: alertKey(alert) })}
                        aria-label={`Open alert: ${alert.title} on ${alert.entity}`}
                      >
                        <Chip severity={alert.severity} small />
                        <span className="drill-row-main">
                          <b>{alert.title}</b>
                          <small className="mono-value">{alert.entity}</small>
                        </span>
                        <strong className="num" style={{ color: sevColor(alert.severity) }}>{alert.risk_score}</strong>
                      </button>
                    ))}
                  </div>

                  {alerts.length > visible.length && (
                    <button className="show-more" onClick={() => dispatch({ type: 'show_more_alerts' })}>
                      Show 60 more · {fmt(alerts.length - visible.length)} hidden
                    </button>
                  )}

                  {alerts.length > 0 && (
                    <p className="drill-foot">
                      Showing <span className="num">{fmt(visible.length)}</span> of <span className="num">{fmt(alerts.length)}</span> matching alerts.
                      Rendered in pages so a large snapshot cannot stall the browser.
                    </p>
                  )}
                </>
              )}
            </div>
          </motion.aside>
        </>
      )}
    </AnimatePresence>
  )
}
