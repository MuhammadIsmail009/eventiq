import { motion } from 'framer-motion'
import { useEffect } from 'react'
import type { Alert, Incident } from '../report'
import { Chip, fmt } from '../ui'
import { techniqueInfo } from './techniques'

function useEscape(onClose: () => void) {
  useEffect(() => {
    const close = (event: KeyboardEvent) => {
      if (event.key === 'Escape') onClose()
    }
    window.addEventListener('keydown', close)
    return () => window.removeEventListener('keydown', close)
  }, [onClose])
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="detail-field">
      <dt>{label}</dt>
      <dd>{children}</dd>
    </div>
  )
}

function EvidenceObject({ label, value }: { label: string; value: Record<string, unknown> }) {
  const rows = Object.entries(value ?? {})
  if (!rows.length) return null
  return (
    <section className="evidence-block">
      <h4>{label}</h4>
      <dl>
        {rows.map(([key, item]) => (
          <div key={key}>
            <dt>{key.replace(/_/g, ' ')}</dt>
            <dd className="mono-value">{typeof item === 'object' ? JSON.stringify(item) : String(item)}</dd>
          </div>
        ))}
      </dl>
    </section>
  )
}

function PanelFrame({
  eyebrow,
  title,
  onClose,
  children,
}: {
  eyebrow: string
  title: string
  onClose: () => void
  children: React.ReactNode
}) {
  useEscape(onClose)
  return (
    <motion.aside
      className="investigation-panel"
      role="complementary"
      aria-label={`${eyebrow} details`}
      initial={{ opacity: 0, x: 18 }}
      animate={{ opacity: 1, x: 0 }}
      exit={{ opacity: 0, x: 12 }}
      transition={{ type: 'spring', stiffness: 390, damping: 38 }}
    >
      <div className="panel-head">
        <div>
          <span className="panel-eyebrow">{eyebrow}</span>
          <h3>{title}</h3>
        </div>
        <button className="panel-close" onClick={onClose} aria-label={`Close ${eyebrow} details`}>Close</button>
      </div>
      <div className="panel-content">{children}</div>
    </motion.aside>
  )
}

/**
 * Alert evidence body without a frame, so the drill drawer can render it
 * inline after the reviewer picks a row.
 */
export function AlertEvidence({ alert }: { alert: Alert }) {
  return (
    <div aria-label={`Rule ${alert.rule.id} evidence`}>
      <span className="panel-eyebrow">Rule {alert.rule.id}</span>
      <h3 className="drill-detail-title">{alert.title}</h3>
      <div className="detail-lead">
        <Chip severity={alert.severity} />
        <span><b className="num">{alert.risk_score}</b>/100 relative triage score</span>
      </div>
      <p className="detail-copy">{alert.rule.description}</p>
      <dl className="detail-grid">
        <Field label="Primary entity"><span className="mono-value">{alert.entity}</span></Field>
        <Field label="Rule level"><span className="num">{alert.rule.level}</span></Field>
        <Field label="First seen"><span className="mono-value">{alert.first_seen}</span></Field>
        <Field label="Last seen"><span className="mono-value">{alert.last_seen}</span></Field>
        <Field label="State">Read-only finding</Field>
      </dl>
      <section className="technique-block">
        <h4>Observed MITRE ATT&amp;CK mappings</h4>
        <div className="technique-list">
          {alert.rule.mitre.id.map((id) => {
            const info = techniqueInfo(id)
            return <span key={id}><b className="num">{id}</b> · {info.name}</span>
          })}
        </div>
      </section>
      <EvidenceObject label="Why it fired" value={alert.evidence} />
      <EvidenceObject label="Detector data" value={alert.data} />
      {alert.sample_rows.length > 0 && (
        <section className="evidence-block">
          <h4>Sample source row IDs</h4>
          <p className="mono-value">{alert.sample_rows.join(', ')}</p>
        </section>
      )}
    </div>
  )
}

export function IncidentDetails({
  incident,
  relatedAlertCount,
  onClose,
  onViewRelated,
}: {
  incident: Incident
  relatedAlertCount: number
  onClose: () => void
  onViewRelated: () => void
}) {
  return (
    <PanelFrame eyebrow={incident.id} title={incident.title} onClose={onClose}>
      <div className="detail-lead">
        <Chip severity={incident.severity} />
        <span><b className="num">{incident.risk_score}</b>/100 relative triage score</span>
      </div>
      <p className="detail-copy">{incident.narrative}</p>
      <dl className="detail-grid">
        <Field label="Grouping rule"><span className="num">{incident.rule_id}</span></Field>
        <Field label="Basis">{incident.basis}</Field>
        <Field label="Primary entity"><span className="mono-value">{incident.primary_entity}</span></Field>
        <Field label="First seen"><span className="mono-value">{incident.first_seen}</span></Field>
        <Field label="Last seen"><span className="mono-value">{incident.last_seen}</span></Field>
        <Field label="Aggregated alerts"><span className="num">{fmt(incident.alert_count)}</span></Field>
        <Field label="Matched events"><span className="num">{fmt(incident.event_count)}</span></Field>
        <Field label="Affected entities"><span className="num">{fmt(incident.affected_count)}</span></Field>
      </dl>
      <section className="technique-block">
        <h4>Observed MITRE ATT&amp;CK mappings</h4>
        <div className="technique-list">
          {incident.techniques.map((id) => {
            const info = techniqueInfo(id)
            return <span key={id}><b className="num">{id}</b> · {info.name}</span>
          })}
        </div>
      </section>
      <section className="evidence-block">
        <h4>Affected entities shown in report</h4>
        <p className="mono-value">{incident.affected_entities.join(', ') || 'none'}</p>
        {incident.affected_count > incident.affected_entities.length && (
          <p className="scope-copy">
            Display list capped at {fmt(incident.affected_entities.length)}. Related-alert navigation uses the uncapped rule relationship.
          </p>
        )}
      </section>
      <button className="primary-action" onClick={onViewRelated}>
        View {fmt(relatedAlertCount)} related alerts
      </button>
    </PanelFrame>
  )
}
