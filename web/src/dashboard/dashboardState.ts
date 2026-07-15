import type { Alert, EntityRisk, Incident, Report, Severity } from '../report'
import { techniqueInfo } from './techniques'

export type DashboardView = 'overview' | 'investigate' | 'trust'
export type AlertSort = 'risk' | 'recent' | 'rule' | 'severity'

export interface DashboardFilters {
  query: string
  severity: Severity | 'all'
  ruleId: number | null
  entity: string | null
  technique: string | null
}

export interface DashboardState {
  view: DashboardView
  filters: DashboardFilters
  alertSort: AlertSort
  visibleAlertLimit: number
  selectedAlertKey: string | null
  selectedIncidentId: string | null
  /**
   * The drawer's own scope, layered on top of the toolbar filters but never
   * merged into them.
   *
   * Drilling opens alert evidence over the current workspace instead of
   * navigating to it, so closing the drawer leaves the page exactly as it was.
   * A chart click must not silently re-filter the dashboard behind it.
   * `null` means the drawer is closed.
   */
  drill: Partial<DashboardFilters> | null
}

export const DEFAULT_FILTERS: Readonly<DashboardFilters> = Object.freeze({
  query: '',
  severity: 'all',
  ruleId: null,
  entity: null,
  technique: null,
})

export const FILTER_SCOPE = Object.freeze({
  alerts: ['query', 'severity', 'ruleId', 'entity', 'technique'] as const,
  incidents: ['query', 'severity', 'ruleId', 'entity', 'technique'] as const,
  entities: ['query', 'severity', 'ruleId', 'entity', 'technique'] as const,
  // Raw volume and profile fields are pre-aggregated by Python. They cannot be
  // honestly recomputed from the alert envelope in the browser.
  wholeFile: [] as const,
})

export const METRIC_UNITS = Object.freeze({
  matched: 'unique matched events',
  alerts: 'aggregated alerts',
  incidents: 'grouped incidents',
  entities: 'primary alert entities',
  dailyVolume: 'all ingested events',
})

type SetFilterAction = {
  [K in keyof DashboardFilters]: {
    type: 'set_filter'
    key: K
    value: DashboardFilters[K]
  }
}[keyof DashboardFilters]

export type DashboardAction =
  | { type: 'navigate'; view: DashboardView }
  | { type: 'drill'; filters: Partial<DashboardFilters> }
  | { type: 'close_drill' }
  | SetFilterAction
  | { type: 'reset_filters' }
  | { type: 'set_alert_sort'; sort: AlertSort }
  | { type: 'show_more_alerts' }
  | { type: 'select_alert'; key: string | null }
  | { type: 'select_incident'; id: string | null }

export function createInitialDashboardState(): DashboardState {
  return {
    view: 'overview',
    filters: { ...DEFAULT_FILTERS },
    alertSort: 'risk',
    visibleAlertLimit: 40,
    selectedAlertKey: null,
    selectedIncidentId: null,
    drill: null,
  }
}

export function dashboardReducer(state: DashboardState, action: DashboardAction): DashboardState {
  switch (action.type) {
    case 'navigate':
      return {
        ...state,
        view: action.view,
        drill: null,
        selectedAlertKey: null,
        selectedIncidentId: action.view === 'investigate' ? state.selectedIncidentId : null,
      }
    case 'drill':
      return {
        ...state,
        drill: action.filters,
        visibleAlertLimit: 40,
        selectedAlertKey: null,
      }
    case 'close_drill':
      return { ...state, drill: null, selectedAlertKey: null }
    case 'set_filter':
      return {
        ...state,
        filters: { ...state.filters, [action.key]: action.value },
        visibleAlertLimit: 40,
        selectedAlertKey: null,
        selectedIncidentId: null,
      }
    case 'reset_filters':
      return {
        ...state,
        filters: { ...DEFAULT_FILTERS },
        visibleAlertLimit: 40,
        selectedAlertKey: null,
        selectedIncidentId: null,
      }
    case 'set_alert_sort':
      return { ...state, alertSort: action.sort, visibleAlertLimit: 40 }
    case 'show_more_alerts':
      return { ...state, visibleAlertLimit: state.visibleAlertLimit + 60 }
    case 'select_alert':
      return { ...state, selectedAlertKey: action.key }
    case 'select_incident':
      return { ...state, selectedIncidentId: action.id }
  }
}

const SEVERITY_RANK: Record<Severity, number> = {
  CRITICAL: 5,
  HIGH: 4,
  MEDIUM: 3,
  LOW: 2,
  INFO: 1,
}

function includesQuery(values: Array<string | number>, query: string): boolean {
  const needle = query.trim().toLocaleLowerCase()
  if (!needle) return true
  return values.some((value) => String(value).toLocaleLowerCase().includes(needle))
}

function alertMatches(alert: Alert, filters: DashboardFilters): boolean {
  if (filters.severity !== 'all' && alert.severity !== filters.severity) return false
  if (filters.ruleId !== null && alert.rule.id !== filters.ruleId) return false
  if (filters.entity !== null && alert.entity !== filters.entity) return false
  if (filters.technique !== null && !alert.rule.mitre.id.includes(filters.technique)) return false
  return includesQuery(
    [alert.title, alert.entity, alert.rule.id, alert.rule.description, ...alert.rule.mitre.id],
    filters.query,
  )
}

function compareText(a: string, b: string): number {
  return a.localeCompare(b, 'en')
}

function alertTieBreak(a: Alert, b: Alert): number {
  return (
    a.rule.id - b.rule.id
    || compareText(a.entity, b.entity)
    || compareText(a.first_seen, b.first_seen)
    || compareText(a.title, b.title)
  )
}

function compareAlerts(a: Alert, b: Alert, sort: AlertSort): number {
  switch (sort) {
    case 'recent':
      return compareText(b.last_seen, a.last_seen) || alertTieBreak(a, b)
    case 'rule':
      return a.rule.id - b.rule.id || compareText(a.entity, b.entity) || compareText(a.first_seen, b.first_seen)
    case 'severity':
      return SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] || b.risk_score - a.risk_score || alertTieBreak(a, b)
    case 'risk':
      return b.risk_score - a.risk_score || alertTieBreak(a, b)
  }
}

export function selectFilteredAlerts(
  report: Report,
  filters: DashboardFilters,
  sort: AlertSort,
): Alert[] {
  return report.alerts.filter((alert) => alertMatches(alert, filters)).sort((a, b) => compareAlerts(a, b, sort))
}

function incidentMatches(
  incident: Incident,
  filters: DashboardFilters,
  relatedEntities: readonly string[],
): boolean {
  if (filters.severity !== 'all' && incident.severity !== filters.severity) return false
  if (filters.ruleId !== null && incident.rule_id !== filters.ruleId) return false
  if (filters.entity !== null && !relatedEntities.includes(filters.entity)) return false
  if (filters.technique !== null && !incident.techniques.includes(filters.technique)) return false
  return includesQuery(
    [
      incident.id,
      incident.rule_id,
      incident.title,
      incident.category,
      incident.basis,
      incident.primary_entity,
      incident.narrative,
      ...relatedEntities,
      ...incident.techniques,
    ],
    filters.query,
  )
}

export function selectFilteredIncidents(report: Report, filters: DashboardFilters): Incident[] {
  const entitiesByRule = new Map<number, string[]>()
  for (const alert of report.alerts) {
    const entities = entitiesByRule.get(alert.rule.id)
    if (entities) {
      entities.push(alert.entity)
    } else {
      entitiesByRule.set(alert.rule.id, [alert.entity])
    }
  }
  return report.incidents
    .filter((incident) => incidentMatches(incident, filters, entitiesByRule.get(incident.rule_id) ?? []))
    .sort((a, b) => b.risk_score - a.risk_score || b.event_count - a.event_count || a.rule_id - b.rule_id)
}

function entityMatches(entity: EntityRisk, filters: DashboardFilters): boolean {
  if (filters.entity !== null && entity.entity !== filters.entity) return false
  return includesQuery(
    [entity.entity, ...entity.contributing_rules, ...entity.techniques],
    filters.query,
  )
}

export function selectFilteredEntities(report: Report, filters: DashboardFilters): EntityRisk[] {
  // EntityRisk.severity is a risk band, not alert severity. Apply the global
  // detection filters to alerts first, then use the matching primary entities
  // only as membership. The displayed risk score/band remains precomputed.
  const hasDetectionFilter = (
    filters.severity !== 'all'
    || filters.ruleId !== null
    || filters.technique !== null
  )
  const matchingAlertEntities = hasDetectionFilter
    ? new Set(
        selectFilteredAlerts(
          report,
          {
            ...DEFAULT_FILTERS,
            severity: filters.severity,
            ruleId: filters.ruleId,
            technique: filters.technique,
          },
          'risk',
        ).map((alert) => alert.entity),
      )
    : null
  return report.entity_risk
    .filter((entity) => (
      (matchingAlertEntities === null || matchingAlertEntities.has(entity.entity))
      && entityMatches(entity, filters)
    ))
    .sort((a, b) => b.risk_score - a.risk_score || compareText(a.entity, b.entity))
}

export function selectRelatedAlerts(report: Report, incident: Incident): Alert[] {
  return report.alerts
    .filter((alert) => alert.rule.id === incident.rule_id)
    .sort((a, b) => compareAlerts(a, b, 'risk'))
}

export function alertKey(alert: Alert): string {
  return `${alert.rule.id}\u0000${alert.entity}\u0000${alert.first_seen}\u0000${alert.last_seen}`
}

export function selectMatchingPrimaryEntityCount(alerts: Alert[]): number {
  return new Set(alerts.map((alert) => alert.entity)).size
}

/**
 * The drawer shows the toolbar filters with its own drill scope layered on
 * top. Kept separate from `state.filters` so closing the drawer cannot leave
 * the workspace filtered by something the reviewer only meant to peek at.
 */
export function selectDrillFilters(
  filters: DashboardFilters,
  drill: Partial<DashboardFilters>,
): DashboardFilters {
  return { ...filters, ...drill }
}

/**
 * Plain-language description of what the drawer is currently scoped to. The
 * drawer always states this, so the same list opened from two places never
 * looks like the same unexplained screen.
 *
 * Rules are named, not numbered: "malicious powershell" is a sentence a
 * reviewer can follow, "rule 100200" is an id they have to go look up.
 */
export function describeFilters(filters: DashboardFilters, report?: Report): string {
  const parts: string[] = []
  if (filters.severity !== 'all') parts.push(`${filters.severity.toLowerCase()} severity`)
  if (filters.ruleId !== null) parts.push(describeRule(filters.ruleId, report))
  if (filters.entity !== null) parts.push(filters.entity)
  if (filters.technique !== null) parts.push(`${filters.technique} · ${techniqueInfo(filters.technique).name}`)
  if (filters.query.trim()) parts.push(`"${filters.query.trim()}"`)
  return parts.length ? parts.join(' · ') : 'all alerts in this snapshot'
}

function describeRule(ruleId: number, report?: Report): string {
  const category = report?.categories.find((item) => item.rule_id === ruleId)?.category
  return category ? category.replace(/_/g, ' ') : `rule ${ruleId}`
}

export function selectWholeFileData(report: Report) {
  return {
    input: report.input,
    summary: report.summary,
    overview: report.overview,
  }
}
