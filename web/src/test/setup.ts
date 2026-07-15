import '@testing-library/jest-dom/vitest'
import { cleanup } from '@testing-library/react'
import { afterEach } from 'vitest'

afterEach(cleanup)

Object.defineProperty(window, 'matchMedia', {
  writable: true,
  value: (query: string): MediaQueryList => ({
    matches: query.includes('prefers-reduced-motion'),
    media: query,
    onchange: null,
    addListener: () => undefined,
    removeListener: () => undefined,
    addEventListener: () => undefined,
    removeEventListener: () => undefined,
    dispatchEvent: () => false,
  }),
})

class ImmediateIntersectionObserver implements IntersectionObserver {
  readonly root = null
  readonly rootMargin = '0px'
  readonly thresholds = [0]

  constructor(private readonly callback: IntersectionObserverCallback) {}

  observe(target: Element): void {
    const rect = target.getBoundingClientRect()
    this.callback(
      [{
        boundingClientRect: rect,
        intersectionRatio: 1,
        intersectionRect: rect,
        isIntersecting: true,
        rootBounds: null,
        target,
        time: performance.now(),
      }],
      this,
    )
  }

  disconnect(): void {}
  takeRecords(): IntersectionObserverEntry[] { return [] }
  unobserve(): void {}
}

Object.defineProperty(globalThis, 'IntersectionObserver', {
  writable: true,
  value: ImmediateIntersectionObserver,
})
