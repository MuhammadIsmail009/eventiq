import { motion, useReducedMotion } from 'framer-motion'
import { useState } from 'react'
import type { Tally } from './report'
import { fmt } from './ui'

/**
 * Charts as inline SVG. No chart library, no CDN.
 *
 * Every chart carries a visually-hidden data table so the numbers are reachable
 * by a screen reader and by anyone who cannot use a hover tooltip. The chart is
 * the enhancement; the table is the data.
 */

function DataTable({ caption, rows, unit }: { caption: string; rows: Tally[]; unit: string }) {
  return (
    <table style={visuallyHidden}>
      <caption>{caption}</caption>
      <thead>
        <tr>
          <th scope="col">Label</th>
          <th scope="col">{unit}</th>
        </tr>
      </thead>
      <tbody>
        {rows.map(([label, n]) => (
          <tr key={label}>
            <th scope="row">{label}</th>
            <td>{n}</td>
          </tr>
        ))}
      </tbody>
    </table>
  )
}

/** Events per day across the file's span. Flat line, no decorative fill. */
export function VolumeChart({ data }: { data: Tally[] }) {
  const [hover, setHover] = useState<number | null>(null)
  const w = 960
  const h = 150
  if (!data.length) return null

  const max = Math.max(...data.map(([, c]) => c)) || 1
  const step = data.length > 1 ? w / (data.length - 1) : 0
  const pts = data.map(([, c], i) => {
    const x = data.length > 1 ? i * step : w / 2
    const y = h - (c / max) * (h - 16) - 6
    return [x, y] as const
  })
  const line = pts.map(([x, y]) => `${x},${y}`).join(' ')
  const avg = Math.round(data.reduce((s, [, c]) => s + c, 0) / data.length)
  const active = hover !== null ? data[hover] : null

  return (
    <div style={{ position: 'relative' }}>
      <div style={chartHead}>
        <span style={{ color: 'var(--tx3)' }}>events per day</span>
        <span style={{ color: 'var(--tx3)' }}>
          {active ? (
            <>
              <b style={{ color: 'var(--tx)' }}>{active[0]}</b>{' '}
              <b style={{ color: 'var(--signal)' }} className="num">
                {fmt(active[1])}
              </b>
            </>
          ) : (
            <>
              avg <b className="num" style={{ color: 'var(--tx2)' }}>{fmt(avg)}</b> / day · peak{' '}
              <b className="num" style={{ color: 'var(--tx2)' }}>{fmt(max)}</b>
            </>
          )}
        </span>
      </div>

      <svg
        viewBox={`0 0 ${w} ${h}`}
        style={{ width: '100%', height: 150, display: 'block', overflow: 'visible' }}
        role="img"
        aria-label={`Events per day from ${data[0]![0]} to ${data[data.length - 1]![0]}`}
        onPointerLeave={() => setHover(null)}
        onPointerMove={(e) => {
          const box = e.currentTarget.getBoundingClientRect()
          const rel = ((e.clientX - box.left) / box.width) * w
          setHover(Math.max(0, Math.min(data.length - 1, Math.round(rel / (step || 1)))))
        }}
      >
        <motion.polyline
          points={line}
          fill="none"
          stroke="var(--signal)"
          strokeWidth="1.5"
          initial={{ pathLength: 0 }}
          animate={{ pathLength: 1 }}
          transition={{ duration: 0.5, ease: [0.22, 1, 0.36, 1] }}
        />
        {hover !== null && pts[hover] && (
          <>
            <line x1={pts[hover]![0]} y1={0} x2={pts[hover]![0]} y2={h} stroke="var(--bd-hi)" strokeWidth="1" />
            <circle cx={pts[hover]![0]} cy={pts[hover]![1]} r="3.5" fill="var(--signal)" />
          </>
        )}
      </svg>

      <div style={{ ...chartHead, marginTop: 4, fontSize: 10 }}>
        <span style={{ color: 'var(--tx3)' }}>{data[0]![0]}</span>
        <span style={{ color: 'var(--tx3)' }}>{data[data.length - 1]![0]}</span>
      </div>
      <DataTable caption="Events per day" rows={data} unit="Events" />
    </div>
  )
}

/** Horizontal bars for the top-N tallies. */
export function BarList({
  data,
  label,
  color = 'var(--sev-low)',
  max: forcedMax,
}: {
  data: Tally[]
  label: string
  color?: string
  max?: number
}) {
  if (!data.length) return null
  const max = forcedMax ?? (Math.max(...data.map(([, n]) => n)) || 1)

  return (
    <div>
      <div style={{ ...chartHead, marginBottom: 10 }}>
        <span style={{ color: 'var(--tx3)' }}>{label}</span>
      </div>
      <div style={{ display: 'grid', gap: 7 }}>
        {data.map(([name, n]) => (
          <div key={name} style={{ display: 'grid', gridTemplateColumns: '1fr auto', gap: 10, alignItems: 'center' }}>
            <div style={{ position: 'relative', height: 18, display: 'flex', alignItems: 'center' }}>
              <div
                style={{
                  position: 'absolute',
                  inset: '0 auto 0 0',
                  width: `${(n / max) * 100}%`,
                  background: color,
                  opacity: 0.14,
                  borderRadius: 1,
                }}
              />
              <div
                style={{ position: 'absolute', left: 0, top: 0, bottom: 0, width: 2, background: color }}
              />
              <span style={{ position: 'relative', paddingLeft: 8, fontSize: 11.5, color: 'var(--tx)' }}>{name}</span>
            </div>
            <span className="num" style={{ fontSize: 11.5, color: 'var(--tx2)' }}>
              {fmt(n)}
            </span>
          </div>
        ))}
      </div>
      <DataTable caption={label} rows={data} unit="Count" />
    </div>
  )
}

/** A single stacked bar: how the file splits by a categorical field. */
export function SplitBar({ data, label }: { data: Tally[]; label: string }) {
  const [hover, setHover] = useState<string | null>(null)
  const total = data.reduce((s, [, n]) => s + n, 0) || 1
  const palette = ['var(--sev-low)', 'var(--sev-medium)', 'var(--sev-high)', 'var(--sev-info)', 'var(--sev-critical)']

  return (
    <div>
      <div style={{ ...chartHead, marginBottom: 10 }}>
        <span style={{ color: 'var(--tx3)' }}>{label}</span>
        {hover && <span style={{ color: 'var(--tx2)' }}>{hover}</span>}
      </div>
      <div style={{ display: 'flex', height: 8, gap: 2, overflow: 'hidden' }} onPointerLeave={() => setHover(null)}>
        {data.map(([name, n], i) => (
          <motion.div
            key={name}
            style={{ background: palette[i % palette.length], borderRadius: 1, cursor: 'default', flexGrow: n }}
            animate={{ opacity: hover && hover !== `${name} ${fmt(n)}` ? 0.4 : 1 }}
            transition={{ duration: 0.16 }}
            onPointerEnter={() => setHover(`${name} ${fmt(n)}`)}
          />
        ))}
      </div>
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: '4px 14px', marginTop: 10 }}>
        {data.map(([name, n], i) => (
          <span key={name} style={{ fontSize: 10.5, color: 'var(--tx3)', display: 'flex', alignItems: 'center', gap: 5 }}>
            <span style={{ width: 7, height: 7, background: palette[i % palette.length], borderRadius: 1 }} />
            {name}
            <b className="num" style={{ color: 'var(--tx2)' }}>
              {((n / total) * 100).toFixed(1)}%
            </b>
          </span>
        ))}
      </div>
      <DataTable caption={label} rows={data} unit="Count" />
    </div>
  )
}

/**
 * A donut for a categorical split, in the shape Wazuh and Splunk use for
 * severity.
 *
 * The centre carries the real total and every legend row carries its own count
 * and share, so the ring is never the only way to read a number. Legend rows are
 * the keyboard path: an SVG arc cannot take focus.
 */
export function Donut({
  segments,
  centerValue,
  centerLabel,
  label,
  selected,
  onSelect,
}: {
  segments: Array<{ key: string; label: string; value: number; color: string }>
  centerValue: string
  centerLabel: string
  label: string
  selected?: string | null
  onSelect?: (key: string) => void
}) {
  const reduced = useReducedMotion()
  const live = segments.filter((s) => s.value > 0)
  const total = live.reduce((sum, s) => sum + s.value, 0)
  if (!live.length || total === 0) return null

  const r = 54
  const circ = 2 * Math.PI * r
  // One visible gap per arc, but only when there is more than one arc to
  // separate. A lone arc must stay a closed ring.
  const gap = live.length > 1 ? 2 : 0

  let offset = 0
  const arcs = live.map((seg) => {
    const full = (seg.value / total) * circ
    const len = Math.max(full - gap, 0.6)
    const arc = { seg, len, offset }
    offset += full
    return arc
  })

  return (
    <div className="donut-chart">
      <motion.svg
        viewBox="0 0 140 140"
        className="donut-svg"
        role="img"
        aria-label={`${label}. Total ${centerValue}.`}
        initial={reduced ? false : { opacity: 0, scale: 0.97 }}
        animate={{ opacity: 1, scale: 1 }}
        transition={{ duration: 0.22, ease: [0.22, 1, 0.36, 1] }}
      >
        <g transform="rotate(-90 70 70)">
          <circle cx="70" cy="70" r={r} fill="none" stroke="var(--bd)" strokeWidth="1" />
          {arcs.map(({ seg, len, offset: start }) => {
            const active = selected === seg.key
            return (
              <motion.circle
                key={seg.key}
                cx="70"
                cy="70"
                r={r}
                fill="none"
                stroke={seg.color}
                strokeDasharray={`${len} ${circ - len}`}
                strokeDashoffset={-start}
                onClick={onSelect ? () => onSelect(seg.key) : undefined}
                style={{ cursor: onSelect ? 'pointer' : 'default' }}
                animate={{
                  strokeWidth: active ? 22 : 15,
                  opacity: selected && !active ? 0.45 : 1,
                }}
                transition={{ duration: 0.16 }}
              />
            )
          })}
        </g>
        <text x="70" y="66" className="donut-total num">{centerValue}</text>
        <text x="70" y="82" className="donut-caption">{centerLabel}</text>
      </motion.svg>

      <div className="donut-legend">
        {live.map((seg) => {
          const active = selected === seg.key
          const share = ((seg.value / total) * 100).toFixed(1)
          const row = (
            <>
              <span className="donut-swatch" style={{ background: seg.color }} />
              <span className="donut-key">{seg.label}</span>
              <b className="num">{fmt(seg.value)}</b>
              <small className="num">{share}%</small>
            </>
          )
          if (!onSelect) return <div key={seg.key} className="donut-row">{row}</div>
          return (
            <button
              key={seg.key}
              className={active ? 'donut-row selected' : 'donut-row'}
              onClick={() => onSelect(seg.key)}
              aria-pressed={active}
              aria-label={`${seg.label}: ${fmt(seg.value)}, ${share} percent`}
            >
              {row}
            </button>
          )
        })}
      </div>
      <DataTable caption={label} rows={live.map((s) => [s.label, s.value] as Tally)} unit="Count" />
    </div>
  )
}

/**
 * A radial reading of one 0-to-1 score.
 *
 * The arc is proportional to the score and the exact figure sits in the middle,
 * so a 1.000 reads as a closed ring without the number ever being implied rather
 * than stated.
 */
export function ScoreRing({
  value,
  label,
  note,
  color = 'var(--ok)',
}: {
  value: number
  label: string
  note?: string
  color?: string
}) {
  const reduced = useReducedMotion()
  const r = 32
  const circ = 2 * Math.PI * r
  const clamped = Math.max(0, Math.min(1, value))

  return (
    <div className="score-ring">
      <svg viewBox="0 0 80 80" role="img" aria-label={`${label}: ${value.toFixed(3)}`}>
        <g transform="rotate(-90 40 40)">
          <circle cx="40" cy="40" r={r} fill="none" stroke="var(--bd)" strokeWidth="7" />
          <motion.circle
            cx="40"
            cy="40"
            r={r}
            fill="none"
            stroke={color}
            strokeWidth="7"
            strokeLinecap="butt"
            strokeDasharray={circ}
            initial={reduced ? false : { strokeDashoffset: circ }}
            animate={{ strokeDashoffset: circ * (1 - clamped) }}
            transition={{ duration: 0.6, ease: [0.22, 1, 0.36, 1] }}
          />
        </g>
        <text x="40" y="45" className="ring-value num">{value.toFixed(3)}</text>
      </svg>
      <span className="ring-label">{label}</span>
      {note && <small className="ring-note">{note}</small>}
    </div>
  )
}

const chartHead: React.CSSProperties = {
  display: 'flex',
  justifyContent: 'space-between',
  alignItems: 'baseline',
  fontSize: 10.5,
  letterSpacing: '0.08em',
  textTransform: 'uppercase',
}

const visuallyHidden: React.CSSProperties = {
  position: 'absolute',
  width: 1,
  height: 1,
  padding: 0,
  margin: -1,
  overflow: 'hidden',
  clip: 'rect(0,0,0,0)',
  whiteSpace: 'nowrap',
  border: 0,
}
