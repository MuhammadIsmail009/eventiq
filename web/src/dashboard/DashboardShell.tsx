import { AnimatePresence, motion } from 'framer-motion'
import type { Report } from '../report'
import { fmt } from '../ui'
import type { DashboardAction, DashboardState, DashboardView } from './dashboardState'
import FilterToolbar from './FilterToolbar'

const NAV: Array<{ view: DashboardView; index: string; label: string; hint: string }> = [
  { view: 'overview', index: '01', label: 'Overview', hint: 'What the file contains' },
  { view: 'investigate', index: '02', label: 'Investigate', hint: 'What was found, and the proof' },
  { view: 'trust', index: '03', label: 'Trust + Data', hint: 'Whether the results hold up' },
]

function trustLabel(report: Report): string {
  if (report.validation?.overall) return 'scored'
  if (report.validation) return 'labels unsupported'
  return 'labels absent'
}

export default function DashboardShell({
  report,
  state,
  dispatch,
  matchingAlerts,
  onReset,
  children,
}: {
  report: Report
  state: DashboardState
  dispatch: React.Dispatch<DashboardAction>
  matchingAlerts: number
  onReset: () => void
  children: React.ReactNode
}) {
  const { input } = report
  return (
    <motion.main
      className="dashboard-app"
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      transition={{ duration: 0.2 }}
    >
      <header className="app-header">
        <div className="brand-block">
          <div className="wordmark">EVENT<span>IQ</span></div>
          <span className="snapshot-badge">snapshot analysis</span>
        </div>

        <div className="file-context" aria-label="Analysis context">
          <div className="file-name" title={input.file}>{input.file}</div>
          <dl className="context-grid">
            <div><dt>Rows</dt><dd className="num">{fmt(input.rows)}</dd></div>
            <div><dt>Data span</dt><dd className="num">{input.span_start.slice(0, 10)} to {input.span_end.slice(0, 10)}</dd></div>
            <div><dt>Generated</dt><dd className="num">{report.generated_at.replace('T', ' ').slice(0, 19)}</dd></div>
          </dl>
        </div>

        <div className="header-actions">
          <div className="trust-compact" aria-label="Data trust summary">
            <span className={input.schema === 'complete' ? 'status-ok' : 'status-warn'}>{input.schema} schema</span>
            <span className={input.malformed === 0 ? 'status-ok' : 'status-warn'}>{fmt(input.malformed)} malformed</span>
            <span>{trustLabel(report)}</span>
          </div>
          <button className="new-file-button" onClick={onReset}>New file</button>
        </div>
      </header>

      <div className="app-body">
        <nav className="workspace-nav" aria-label="Dashboard workspaces">
          {NAV.map((item) => {
            const active = state.view === item.view
            return (
              <button
                key={item.view}
                className={active ? 'workspace-link active' : 'workspace-link'}
                onClick={() => dispatch({ type: 'navigate', view: item.view })}
                aria-current={active ? 'page' : undefined}
              >
                {active && (
                  <motion.span
                    layoutId="workspace-active"
                    className="workspace-active-mark"
                    transition={{ type: 'spring', stiffness: 420, damping: 36 }}
                  />
                )}
                <span className="workspace-index num">{item.index}</span>
                <span className="workspace-label">
                  <b>{item.label}</b>
                  <small>{item.hint}</small>
                </span>
              </button>
            )
          })}

          <div className="nav-scope">
            <span>Mode</span>
            <b>Local · read only</b>
            <p>No live feed, case actions, or external requests.</p>
          </div>
        </nav>

        <div className="workspace-column">
          <FilterToolbar
            report={report}
            state={state}
            dispatch={dispatch}
            matchingAlerts={matchingAlerts}
          />
          <AnimatePresence mode="wait" initial={false}>
            <motion.div
              className="workspace-view"
              key={state.view}
              initial={{ opacity: 0, x: 6 }}
              animate={{ opacity: 1, x: 0 }}
              exit={{ opacity: 0, x: -4 }}
              transition={{ duration: 0.18, ease: [0.22, 1, 0.36, 1] }}
            >
              {children}
            </motion.div>
          </AnimatePresence>
        </div>
      </div>
    </motion.main>
  )
}
