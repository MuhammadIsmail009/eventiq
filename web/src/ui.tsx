import { animate, motion, useReducedMotion } from 'framer-motion'
import { useEffect, useRef, useState } from 'react'
import type { Severity } from './report'

export const SEVERITY_ORDER: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']

export function sevColor(s: string): string {
  switch (s.toUpperCase()) {
    case 'CRITICAL':
      return 'var(--sev-critical)'
    case 'HIGH':
      return 'var(--sev-high)'
    case 'MEDIUM':
      return 'var(--sev-medium)'
    case 'LOW':
      return 'var(--sev-low)'
    default:
      return 'var(--sev-info)'
  }
}

export const fmt = (n: number): string => n.toLocaleString('en-US')

/**
 * A number that counts up on entry.
 *
 * Respects reduced motion by landing on the final value immediately. Uses
 * tabular numerals so the width does not jitter while it runs.
 */
export function CountUp({
  to,
  duration = 1.1,
  delay = 0,
  format = (n) => fmt(Math.round(n)),
}: {
  to: number
  duration?: number
  delay?: number
  /**
   * Receives the RAW interpolated value, not a rounded one. Rounding before
   * formatting would destroy every fractional metric: a precision of 0.463
   * would render as 0.000 and quietly overstate the tool against its baseline.
   */
  format?: (n: number) => string
}) {
  const reduced = useReducedMotion()
  const [n, setN] = useState(reduced ? to : 0)
  const done = useRef(false)

  useEffect(() => {
    if (reduced || done.current) {
      setN(to)
      return
    }
    done.current = true
    const controls = animate(0, to, {
      duration,
      delay,
      ease: [0.22, 1, 0.36, 1],
      onUpdate: (v) => setN(v),
    })
    return () => controls.stop()
  }, [to, duration, delay, reduced])

  return <span className="num">{format(n)}</span>
}

export function Chip({ severity, small = false }: { severity: string; small?: boolean }) {
  const c = sevColor(severity)
  return (
    <span
      style={{
        color: c,
        border: `1px solid ${c}`,
        background: 'transparent',
        borderRadius: 'var(--r)',
        padding: small ? '0 5px' : '1px 7px',
        fontSize: small ? 9.5 : 10,
        fontWeight: 600,
        letterSpacing: '0.1em',
        textTransform: 'uppercase',
        whiteSpace: 'nowrap',
        lineHeight: 1.7,
      }}
    >
      {severity}
    </span>
  )
}

/** A titled section with a numbered rule, like a report chapter. */
export function Section({
  n,
  title,
  note,
  children,
}: {
  n: string
  title: string
  note?: string
  children: React.ReactNode
}) {
  return (
    <motion.section
      style={{ marginTop: 60 }}
      initial={{ opacity: 0, y: 16 }}
      whileInView={{ opacity: 1, y: 0 }}
      viewport={{ once: true, margin: '-60px' }}
      transition={{ duration: 0.55, ease: [0.22, 1, 0.36, 1] }}
    >
      <div style={{ display: 'flex', alignItems: 'baseline', gap: 12, marginBottom: 6 }}>
        <span style={{ color: 'var(--signal)', fontSize: 10, letterSpacing: '0.2em' }}>{n}</span>
        <h2 style={{ fontSize: 26, fontWeight: 600 }}>{title}</h2>
        <div style={{ flex: 1, height: 1, background: 'var(--bd)' }} />
      </div>
      {note && (
        <p style={{ color: 'var(--tx3)', fontSize: 11.5, marginBottom: 18, maxWidth: '72ch' }}>{note}</p>
      )}
      {children}
    </motion.section>
  )
}

export function Card({
  children,
  style,
}: {
  children: React.ReactNode
  style?: React.CSSProperties
}) {
  return (
    <div
      style={{
        background: 'var(--s1)',
        border: '1px solid var(--bd)',
        borderRadius: 'var(--r)',
        padding: 16,
        ...style,
      }}
    >
      {children}
    </div>
  )
}
