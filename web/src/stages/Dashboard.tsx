import { useMemo, useReducer } from 'react'
import DashboardShell from '../dashboard/DashboardShell'
import DrillDrawer from '../dashboard/DrillDrawer'
import {
  createInitialDashboardState,
  dashboardReducer,
  selectDrillFilters,
  selectFilteredAlerts,
  selectFilteredEntities,
  selectFilteredIncidents,
} from '../dashboard/dashboardState'
import InvestigateView from '../dashboard/views/InvestigateView'
import OverviewView from '../dashboard/views/OverviewView'
import TrustView from '../dashboard/views/TrustView'
import type { Report } from '../report'

/**
 * The served React experience is an operational snapshot workspace.
 *
 * It deliberately differs from the static HTML export, which remains the
 * portable report artifact. Both consume the same report envelope.
 *
 * Three workspaces, one drawer: what happened, dig into it, decide whether to
 * trust it. Drilling never navigates, so the reviewer keeps their place.
 */
export default function Dashboard({ report, onReset }: { report: Report; onReset: () => void }) {
  const [state, dispatch] = useReducer(dashboardReducer, undefined, createInitialDashboardState)
  const alerts = useMemo(
    () => selectFilteredAlerts(report, state.filters, state.alertSort),
    [report, state.filters, state.alertSort],
  )
  const incidents = useMemo(
    () => selectFilteredIncidents(report, state.filters),
    [report, state.filters],
  )
  const entities = useMemo(
    () => selectFilteredEntities(report, state.filters),
    [report, state.filters],
  )
  // The drawer reads the toolbar filters plus its own drill scope. The
  // workspace below keeps reading state.filters alone, which is why closing
  // the drawer never disturbs it.
  const drillFilters = useMemo(
    () => selectDrillFilters(state.filters, state.drill ?? {}),
    [state.filters, state.drill],
  )
  const drillAlerts = useMemo(
    () => (state.drill === null ? [] : selectFilteredAlerts(report, drillFilters, state.alertSort)),
    [report, state.drill, drillFilters, state.alertSort],
  )

  let view: React.ReactNode
  switch (state.view) {
    case 'overview':
      view = (
        <OverviewView
          report={report}
          drill={state.drill}
          alerts={alerts}
          incidents={incidents}
          entities={entities}
          dispatch={dispatch}
        />
      )
      break
    case 'investigate':
      view = (
        <InvestigateView
          report={report}
          incidents={incidents}
          entities={entities}
          filters={state.filters}
          state={state}
          dispatch={dispatch}
        />
      )
      break
    case 'trust':
      view = <TrustView report={report} />
      break
  }

  return (
    <DashboardShell
      report={report}
      state={state}
      dispatch={dispatch}
      matchingAlerts={alerts.length}
      onReset={onReset}
    >
      {view}
      <DrillDrawer
        report={report}
        alerts={drillAlerts}
        scopeFilters={drillFilters}
        state={state}
        dispatch={dispatch}
      />
    </DashboardShell>
  )
}
