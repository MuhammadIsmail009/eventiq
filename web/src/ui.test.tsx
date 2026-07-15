import { render, screen } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import { CountUp } from './ui'

vi.mock('framer-motion', () => ({
  animate: (_from: number, to: number, options: { onUpdate: (value: number) => void }) => {
    options.onUpdate(to)
    return { stop: vi.fn() }
  },
  motion: { section: 'section' },
  useReducedMotion: () => false,
}))

describe('CountUp', () => {
  it('passes the raw fractional value to custom formatting', async () => {
    render(<CountUp to={0.463} format={(n) => n.toFixed(3)} />)
    expect(await screen.findByText('0.463')).toBeInTheDocument()
  })

  it('formats whole numbers with separators by default', async () => {
    render(<CountUp to={12345} />)
    expect(await screen.findByText('12,345')).toBeInTheDocument()
  })
})
