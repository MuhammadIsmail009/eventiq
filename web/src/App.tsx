import { AnimatePresence } from 'framer-motion'
import { useCallback, useState } from 'react'
import './theme.css'
import { analyze, type Report } from './report'
import Boot from './stages/Boot'
import Dashboard from './stages/Dashboard'
import Upload from './stages/Upload'

/**
 * The three-stage flow: boot -> upload -> dashboard.
 *
 * The boot plays once per browser session. Re-analysing a second file should
 * not make an analyst sit through the intro again, so the flag lives in
 * sessionStorage rather than component state.
 */

const BOOT_KEY = 'eventiq.booted'

function bootAlreadyPlayed(): boolean {
  try {
    return sessionStorage.getItem(BOOT_KEY) === '1'
  } catch {
    return false // private mode / storage blocked: just play it
  }
}

function rememberBoot(): void {
  try {
    sessionStorage.setItem(BOOT_KEY, '1')
  } catch {
    /* nothing to do; the boot simply plays again next time */
  }
}

export default function App() {
  const [booted, setBooted] = useState(bootAlreadyPlayed)
  const [report, setReport] = useState<Report | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [fileName, setFileName] = useState<string | null>(null)

  const finishBoot = useCallback(() => {
    rememberBoot()
    setBooted(true)
  }, [])

  const onFile = useCallback(async (file: File) => {
    setBusy(true)
    setError(null)
    setFileName(file.name)
    try {
      const next = await analyze(file)
      setReport(next)
      window.scrollTo({ top: 0 })
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setBusy(false)
    }
  }, [])

  const reset = useCallback(() => {
    setReport(null)
    setError(null)
    setFileName(null)
  }, [])

  return (
    <AnimatePresence mode="wait">
      {!booted ? (
        <Boot key="boot" onDone={finishBoot} />
      ) : report ? (
        <Dashboard key="dash" report={report} onReset={reset} />
      ) : (
        <Upload key="upload" onFile={onFile} busy={busy} error={error} fileName={fileName} />
      )}
    </AnimatePresence>
  )
}
