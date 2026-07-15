import type { Report, Validation } from '../../report'
import { BarList, ScoreRing, SplitBar } from '../../Charts'
import { fmt } from '../../ui'

function Accuracy({ validation }: { validation: Validation | null }) {
  if (!validation) {
    return (
      <article className="panel trust-primary">
        <div className="panel-title"><div><span>Validation</span><h2>Accuracy check unavailable</h2></div></div>
        <p className="trust-explanation">
          This file carried no supported label column to score against, so EventIQ does not invent precision or recall. The findings stand on their detector evidence.
        </p>
      </article>
    )
  }
  if (!validation.overall) {
    return (
      <article className="panel trust-primary">
        <div className="panel-title"><div><span>Validation</span><h2>Accuracy check unavailable</h2></div></div>
        <p className="trust-explanation">
          This file has labels, but none name a campaign EventIQ scores against. Generic labels are not treated as an answer key merely because the column exists.
        </p>
        <div className="trust-facts wide">
          <div><span>Label quality</span><b>{validation.label_audit.quality.replace(/_/g, ' ')}</b></div>
          <div><span>Distinct labels</span><b className="num">{fmt(validation.label_audit.distinct_labels)}</b></div>
          <div><span>Supported campaigns</span><b>{validation.label_audit.known_campaigns_present.join(', ') || 'none'}</b></div>
        </div>
      </article>
    )
  }

  const overall = validation.overall
  const baseline = validation.naive_failed_login_baseline
  return (
    <article className="panel trust-primary">
      <div className="panel-title">
        <div><span>Held-out labels</span><h2>Does it actually work?</h2></div>
        <p>Detection never reads event_type. Supported labels are used only after detection for scoring.</p>
      </div>
      <div className="ring-row">
        <ScoreRing value={overall.precision} label="Precision" note={`${fmt(overall.fp)} false positives`} />
        <ScoreRing value={overall.recall} label="Recall" note={`${fmt(overall.fn)} missed`} />
        <ScoreRing value={overall.f1} label="F1" note={`${fmt(overall.tp)} true positives`} />
        {baseline?.precision !== null && baseline?.precision !== undefined && (
          <ScoreRing
            value={baseline.precision}
            label="Naive baseline"
            note="comparison, not EventIQ"
            color="var(--sev-high)"
          />
        )}
      </div>
      <div className="score-table" role="table" aria-label="Per-rule validation scores">
        <div role="row" className="score-head"><span>Rule</span><span>Campaign</span><span>TP</span><span>FP</span><span>FN</span><span>Precision</span><span>Recall</span><span>F1</span></div>
        {Object.entries(validation.per_rule).map(([name, score]) => (
          <div role="row" key={name}>
            <span><b>{name}</b><small className="num">{score.rule_id}</small></span>
            <span>{score.campaign}</span>
            <span className="num">{fmt(score.tp)}</span>
            <span className="num">{fmt(score.fp)}</span>
            <span className="num">{fmt(score.fn)}</span>
            <span className="num">{score.precision.toFixed(3)}</span>
            <span className="num">{score.recall.toFixed(3)}</span>
            <span className="num">{score.f1.toFixed(3)}</span>
          </div>
        ))}
      </div>
      {validation.unscored.length > 0 && (
        <div className="unscored-list">
          <h3>Fired but not scorable on this file</h3>
          {validation.unscored.map((item) => (
            <p key={item.rule_id}><b className="num">{item.rule_id}</b> · {item.note}</p>
          ))}
        </div>
      )}
    </article>
  )
}

export default function TrustView({ report }: { report: Report }) {
  const { input, overview, coverage } = report
  return (
    <div>
      <div className="view-head">
        <div><span className="view-index">05 / Boundary</span><h1>Trust and data quality</h1></div>
        <p>What can be believed, what was evaluated, and what this snapshot cannot claim.</p>
      </div>

      <section className="trust-layout">
        <Accuracy validation={report.validation} />

        <article className="panel">
          <div className="panel-title"><div><span>Input contract</span><h2>Schema and ingestion</h2></div></div>
          <div className="trust-facts stacked">
            <div><span>Schema</span><b>{input.schema}</b></div>
            <div><span>Rows evaluated</span><b className="num">{fmt(input.rows)}</b></div>
            <div><span>Malformed rows</span><b className="num">{fmt(input.malformed)}</b></div>
            <div><span>Missing optional fields</span><b>{input.missing_optional.join(', ') || 'none'}</b></div>
            <div><span>Rules enabled</span><b className="num">{fmt(coverage.rules_enabled)}</b></div>
          </div>
          <div className="scope-box"><b>Detection scope</b><p>{coverage.scope}</p></div>
        </article>

        <article className="panel profile-panel">
          <div className="panel-title">
            <div><span>Whole file</span><h2>Protocol and status</h2></div>
            <p>Raw input distributions. Detection filters do not change these panels.</p>
          </div>
          <div className="profile-splits">
            <SplitBar data={Object.entries(overview.protocol)} label="protocol" />
            <SplitBar data={Object.entries(overview.status)} label="event status" />
          </div>
        </article>

        <article className="panel profile-panel">
          <div className="panel-title"><div><span>Whole file</span><h2>Top input dimensions</h2></div></div>
          <div className="profile-bars">
            <BarList data={overview.top_destination_ips.slice(0, 6)} label="top destination IPs" color="var(--sev-high)" />
            <BarList data={overview.top_services.slice(0, 6)} label="top services" />
            <BarList data={overview.top_dstports.slice(0, 6)} label="top destination ports" color="var(--sev-medium)" />
            <BarList data={overview.top_usernames.slice(0, 6)} label="top usernames" color="var(--sev-info)" />
          </div>
        </article>

        <article className="panel exclusions-panel">
          <div className="panel-title">
            <div><span>Honest scope</span><h2>What was not checked</h2></div>
            <p>A wrong detector on this data is worse than no detector.</p>
          </div>
          {report.not_detected.length === 0 && <div className="empty-state">No dataset-specific exclusions were supplied.</div>}
          <div className="exclusion-list">
            {report.not_detected.map((item) => (
              <section key={item.name}>
                <h3>{item.name}</h3>
                <p>{item.reason}</p>
                <small>{item.numbers}</small>
              </section>
            ))}
          </div>
        </article>
      </section>
    </div>
  )
}
