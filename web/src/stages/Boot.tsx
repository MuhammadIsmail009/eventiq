import { motion, useReducedMotion } from 'framer-motion'
import { useEffect, useMemo } from 'react'

/**
 * Stage 1: the signal lock.
 *
 * This is not decoration. It is the product in one gesture: a dense field of
 * events, a scan pass, and almost everything resolves to noise while a handful
 * lock as signal. That is 1,000,000 rows becoming 2,481 alerts, before the user
 * has uploaded anything.
 *
 * Skippable by click or any key, auto-advances, and plays once per session
 * (see App.tsx). Under prefers-reduced-motion it does not play at all.
 */

const SWEEP_MS = 1250
const HOLD_MS = 1150

/** Deterministic PRNG. The composition is tuned, so it must not reshuffle. */
function seeded(seed: number): () => number {
  let s = seed >>> 0
  return () => {
    s = (s * 1664525 + 1013904223) >>> 0
    return s / 4294967296
  }
}

interface Mark {
  x: number
  y: number
  signal: boolean
  len: number
}

function useField(): Mark[] {
  return useMemo(() => {
    const rand = seeded(0x5e1f)
    const cols = 26
    const rows = 11
    // Hand-picked so the locks sit off-centre and unevenly. An even spread
    // reads as a loading bar; a clustered one reads as a finding.
    const locks = new Set([37, 94, 118, 141, 187, 203, 246, 259])
    const marks: Mark[] = []
    for (let r = 0; r < rows; r++) {
      for (let c = 0; c < cols; c++) {
        const i = r * cols + c
        marks.push({
          x: (c / (cols - 1)) * 100 + (rand() - 0.5) * 2.4,
          y: (r / (rows - 1)) * 100 + (rand() - 0.5) * 5.5,
          signal: locks.has(i),
          len: 3 + rand() * 5,
        })
      }
    }
    return marks
  }, [])
}

export default function Boot({ onDone }: { onDone: () => void }) {
  const reduced = useReducedMotion()
  const field = useField()

  useEffect(() => {
    if (reduced) {
      onDone()
      return
    }
    const t = setTimeout(onDone, SWEEP_MS + HOLD_MS)
    const skip = () => onDone()
    window.addEventListener('keydown', skip)
    window.addEventListener('pointerdown', skip)
    return () => {
      clearTimeout(t)
      window.removeEventListener('keydown', skip)
      window.removeEventListener('pointerdown', skip)
    }
  }, [onDone, reduced])

  if (reduced) return null

  return (
    <motion.div
      style={styles.wrap}
      exit={{ opacity: 0, y: -6 }}
      transition={{ duration: 0.45, ease: [0.22, 1, 0.36, 1] }}
    >
      <div style={styles.stage}>
        {/* The event field. Each mark resolves as the scan line reaches it. */}
        <div style={styles.field} aria-hidden="true">
          {field.map((m, i) => {
            const at = (m.x / 100) * (SWEEP_MS / 1000)
            return (
              <motion.span
                key={i}
                style={{
                  ...styles.mark,
                  left: `${m.x}%`,
                  top: `${m.y}%`,
                  width: m.len,
                }}
                initial={{ opacity: 0, scaleX: 0.3, backgroundColor: '#46566a' }}
                animate={
                  m.signal
                    ? {
                        opacity: [0, 1, 1],
                        scaleX: [0.3, 1.6, 1.35],
                        backgroundColor: ['#46566a', '#ffb020', '#ffb020'],
                      }
                    : // Noise must stay legible after it resolves. If it fades to
                      // nothing there is no field left, and the few amber locks
                      // read as floating dashes instead of as survivors.
                      { opacity: [0, 0.9, 0.42], scaleX: [0.3, 1, 1] }
                }
                transition={{
                  duration: m.signal ? 0.5 : 0.38,
                  delay: at,
                  ease: [0.22, 1, 0.36, 1],
                  times: [0, 0.45, 1],
                }}
              />
            )
          })}

          {/* The scan line itself. */}
          <motion.div
            style={styles.scan}
            initial={{ left: '-2%', opacity: 0 }}
            animate={{ left: ['-2%', '102%'], opacity: [0, 1, 1, 0] }}
            transition={{
              duration: SWEEP_MS / 1000,
              ease: [0.65, 0, 0.35, 1],
              times: [0, 0.06, 0.9, 1],
            }}
          />
        </div>

        {/* The wordmark resolves after the sweep has done its work. */}
        <motion.div
          style={styles.markWrap}
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ delay: SWEEP_MS / 1000 - 0.1, duration: 0.3 }}
        >
          <motion.h1
            style={styles.word}
            initial={{ letterSpacing: '0.5em', opacity: 0, y: 8 }}
            animate={{ letterSpacing: '0.06em', opacity: 1, y: 0 }}
            transition={{ delay: SWEEP_MS / 1000 - 0.05, duration: 0.75, ease: [0.22, 1, 0.36, 1] }}
          >
            EVENT<span style={{ color: 'var(--signal)' }}>IQ</span>
          </motion.h1>
          <motion.div
            style={styles.rule}
            initial={{ scaleX: 0 }}
            animate={{ scaleX: 1 }}
            transition={{ delay: SWEEP_MS / 1000 + 0.15, duration: 0.5, ease: [0.22, 1, 0.36, 1] }}
          />
          <motion.p
            style={styles.tag}
            initial={{ opacity: 0, y: 6 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: SWEEP_MS / 1000 + 0.3, duration: 0.45 }}
          >
            detect from raw fields · score against held-out labels
          </motion.p>
        </motion.div>
      </div>

      <motion.button
        style={styles.skip}
        onClick={onDone}
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ delay: 0.6 }}
      >
        skip
      </motion.button>
    </motion.div>
  )
}

const styles: Record<string, React.CSSProperties> = {
  wrap: {
    position: 'fixed',
    inset: 0,
    zIndex: 50,
    background: 'var(--bg)',
    display: 'grid',
    placeItems: 'center',
    overflow: 'hidden',
  },
  stage: { position: 'relative', width: 'min(760px, 88vw)' },
  field: { position: 'relative', width: '100%', height: 220 },
  mark: {
    position: 'absolute',
    height: 2,
    borderRadius: 1,
    transformOrigin: 'left center',
    background: '#2b3542',
  },
  scan: {
    position: 'absolute',
    top: -14,
    bottom: -14,
    width: 1,
    background: 'var(--signal)',
  },
  markWrap: {
    position: 'absolute',
    inset: '22% 16%',
    display: 'grid',
    placeContent: 'center',
    textAlign: 'center',
    background: 'var(--bg)',
    border: '1px solid var(--bd)',
  },
  word: {
    fontFamily: 'var(--display)',
    fontSize: 'clamp(56px, 9vw, 104px)',
    fontWeight: 700,
    textTransform: 'uppercase',
  },
  rule: {
    height: 1,
    background: 'var(--signal)',
    margin: '14px auto 0',
    width: '78%',
    transformOrigin: 'center',
  },
  tag: {
    marginTop: 12,
    fontSize: 11,
    letterSpacing: '0.16em',
    color: 'var(--tx3)',
    textTransform: 'lowercase',
  },
  skip: {
    position: 'absolute',
    right: 22,
    bottom: 18,
    fontSize: 11,
    letterSpacing: '0.18em',
    color: 'var(--tx3)',
    textTransform: 'uppercase',
    padding: '6px 10px',
  },
}
