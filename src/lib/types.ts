export interface DomElement {
  id: string
  tag: string
  text: string
  type: string
  href: string
  name: string
  placeholder: string
  className: string
  bounds: {
    x: number
    y: number
    width: number
    height: number
  }
}

export interface Message {
  id: string
  content: string
  role: 'user' | 'assistant'
  timestamp: Date
  details?: string // Expandable details (shown on "Read more")
  type?: 'text' | 'script' | 'action' | 'error' | 'success' // Message type for styling
}

export type ViewportType = 'desktop' | 'laptop' | 'tablet' | 'mobile'

export interface ViewportSize {
  width: number
  height: number
  label: string
}

export const VIEWPORTS: Record<ViewportType, ViewportSize> = {
  desktop: { width: 0, height: 0, label: 'Desktop' },
  laptop: { width: 1366, height: 768, label: 'Laptop' },
  tablet: { width: 768, height: 1024, label: 'Tablet' },
  mobile: { width: 375, height: 812, label: 'Mobile' },
}
