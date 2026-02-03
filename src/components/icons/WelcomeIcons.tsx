// Premium custom icons for Yalitest welcome flow
// High-quality, distinctive SVG icons with professional design

interface IconProps {
  className?: string
  strokeWidth?: number
}

// Shield with checkmark - Security
export function IconShieldCheck({ className = 'w-6 h-6', strokeWidth = 1.5 }: IconProps) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
      <path
        d="M12 2L4 5.5V11.5C4 16.19 7.4 20.55 12 22C16.6 20.55 20 16.19 20 11.5V5.5L12 2Z"
        stroke="currentColor"
        strokeWidth={strokeWidth}
        strokeLinecap="round"
        strokeLinejoin="round"
      />
      <path
        d="M9 12L11 14L15 10"
        stroke="currentColor"
        strokeWidth={strokeWidth}
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  )
}

// Bug with magnifier - Bug Detection
export function IconBugSearch({ className = 'w-6 h-6', strokeWidth = 1.5 }: IconProps) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
      <path
        d="M8 8V7C8 4.79 9.79 3 12 3C14.21 3 16 4.79 16 7V8"
        stroke="currentColor"
        strokeWidth={strokeWidth}
        strokeLinecap="round"
      />
      <path
        d="M5 10H19"
        stroke="currentColor"
        strokeWidth={strokeWidth}
        strokeLinecap="round"
      />
      <rect
        x="7" y="8" width="10" height="9" rx="3"
        stroke="currentColor"
        strokeWidth={strokeWidth}
      />
      <path d="M7 12H5M19 12H17" stroke="currentColor" strokeWidth={strokeWidth} strokeLinecap="round"/>
      <path d="M7 15L5 16M17 15L19 16" stroke="currentColor" strokeWidth={strokeWidth} strokeLinecap="round"/>
      <circle cx="18" cy="18" r="3" stroke="currentColor" strokeWidth={strokeWidth}/>
      <path d="M21 21L20 20" stroke="currentColor" strokeWidth={strokeWidth} strokeLinecap="round"/>
    </svg>
  )
}

// Eye with scan lines - Visual Testing
export function IconEyeScan({ className = 'w-6 h-6', strokeWidth = 1.5 }: IconProps) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
      <path
        d="M2.5 12C2.5 12 5.5 5 12 5C18.5 5 21.5 12 21.5 12C21.5 12 18.5 19 12 19C5.5 19 2.5 12 2.5 12Z"
        stroke="currentColor"
        strokeWidth={strokeWidth}
        strokeLinecap="round"
        strokeLinejoin="round"
      />
      <circle
        cx="12" cy="12" r="3"
        stroke="currentColor"
        strokeWidth={strokeWidth}
      />
      <path d="M12 2V4" stroke="currentColor" strokeWidth={strokeWidth} strokeLinecap="round"/>
      <path d="M12 20V22" stroke="currentColor" strokeWidth={strokeWidth} strokeLinecap="round"/>
      <path d="M4.5 4.5L6 6" stroke="currentColor" strokeWidth={strokeWidth} strokeLinecap="round"/>
      <path d="M18 18L19.5 19.5" stroke="currentColor" strokeWidth={strokeWidth} strokeLinecap="round"/>
    </svg>
  )
}

// Accessibility icon - Universal Access
export function IconAccessibility({ className = 'w-6 h-6', strokeWidth = 1.5 }: IconProps) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
      <circle cx="12" cy="4.5" r="2" stroke="currentColor" strokeWidth={strokeWidth}/>
      <path
        d="M12 7V12M12 12L8 20M12 12L16 20"
        stroke="currentColor"
        strokeWidth={strokeWidth}
        strokeLinecap="round"
        strokeLinejoin="round"
      />
      <path
        d="M5 9L12 10L19 9"
        stroke="currentColor"
        strokeWidth={strokeWidth}
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  )
}

// Lightning bolt - Speed/Performance
export function IconBolt({ className = 'w-6 h-6', strokeWidth = 1.5 }: IconProps) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
      <path
        d="M13 2L4 14H12L11 22L20 10H12L13 2Z"
        stroke="currentColor"
        strokeWidth={strokeWidth}
        strokeLinecap="round"
        strokeLinejoin="round"
        fill="currentColor"
        fillOpacity="0.1"
      />
    </svg>
  )
}

// Clock with speed lines - Time Saving
export function IconClockFast({ className = 'w-6 h-6', strokeWidth = 1.5 }: IconProps) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
      <circle cx="12" cy="12" r="9" stroke="currentColor" strokeWidth={strokeWidth}/>
      <path d="M12 6V12L15 15" stroke="currentColor" strokeWidth={strokeWidth} strokeLinecap="round" strokeLinejoin="round"/>
      <path d="M2 9H5" stroke="currentColor" strokeWidth={strokeWidth} strokeLinecap="round" opacity="0.5"/>
      <path d="M2 12H4" stroke="currentColor" strokeWidth={strokeWidth} strokeLinecap="round" opacity="0.7"/>
      <path d="M2 15H5" stroke="currentColor" strokeWidth={strokeWidth} strokeLinecap="round" opacity="0.5"/>
    </svg>
  )
}

// Globe with cursor - Web Testing
export function IconGlobeTest({ className = 'w-6 h-6', strokeWidth = 1.5 }: IconProps) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
      <circle cx="12" cy="12" r="9" stroke="currentColor" strokeWidth={strokeWidth}/>
      <path d="M3 12H21" stroke="currentColor" strokeWidth={strokeWidth} strokeLinecap="round"/>
      <path d="M12 3C12 3 8 7 8 12C8 17 12 21 12 21" stroke="currentColor" strokeWidth={strokeWidth} strokeLinecap="round"/>
      <path d="M12 3C12 3 16 7 16 12C16 17 12 21 12 21" stroke="currentColor" strokeWidth={strokeWidth} strokeLinecap="round"/>
      <path d="M18 17L21 20L19 22L18 17Z" fill="currentColor" stroke="currentColor" strokeWidth={strokeWidth} strokeLinejoin="round"/>
    </svg>
  )
}

// Chat bubble with sparkle - AI Assistant
export function IconChatAI({ className = 'w-6 h-6', strokeWidth = 1.5 }: IconProps) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
      <path
        d="M21 12C21 16.418 16.97 20 12 20C10.5 20 9.08 19.7 7.8 19.16L3 21L4.33 17.14C3.5 15.66 3 13.9 3 12C3 7.582 7.03 4 12 4C16.97 4 21 7.582 21 12Z"
        stroke="currentColor"
        strokeWidth={strokeWidth}
        strokeLinecap="round"
        strokeLinejoin="round"
      />
      <path d="M12 8V8.5M12 8.5C10.89 8.5 10 9.39 10 10.5V11H14V10.5C14 9.39 13.11 8.5 12 8.5Z" stroke="currentColor" strokeWidth={strokeWidth} strokeLinecap="round"/>
      <circle cx="12" cy="14" r="0.5" fill="currentColor"/>
    </svg>
  )
}

// Checkmark in circle with rays - Success/Complete
export function IconCheckSuccess({ className = 'w-6 h-6', strokeWidth = 1.5 }: IconProps) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
      <circle cx="12" cy="12" r="8" stroke="currentColor" strokeWidth={strokeWidth}/>
      <path d="M8.5 12L11 14.5L15.5 10" stroke="currentColor" strokeWidth={strokeWidth} strokeLinecap="round" strokeLinejoin="round"/>
      <path d="M12 2V4" stroke="currentColor" strokeWidth={strokeWidth} strokeLinecap="round" opacity="0.6"/>
      <path d="M12 20V22" stroke="currentColor" strokeWidth={strokeWidth} strokeLinecap="round" opacity="0.6"/>
      <path d="M2 12H4" stroke="currentColor" strokeWidth={strokeWidth} strokeLinecap="round" opacity="0.6"/>
      <path d="M20 12H22" stroke="currentColor" strokeWidth={strokeWidth} strokeLinecap="round" opacity="0.6"/>
    </svg>
  )
}

// Terminal with code - Developer Tool
export function IconTerminalCode({ className = 'w-6 h-6', strokeWidth = 1.5 }: IconProps) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
      <rect x="3" y="4" width="18" height="16" rx="2" stroke="currentColor" strokeWidth={strokeWidth}/>
      <path d="M7 9L10 12L7 15" stroke="currentColor" strokeWidth={strokeWidth} strokeLinecap="round" strokeLinejoin="round"/>
      <path d="M13 15H17" stroke="currentColor" strokeWidth={strokeWidth} strokeLinecap="round"/>
      <path d="M3 8H21" stroke="currentColor" strokeWidth={strokeWidth} opacity="0.3"/>
    </svg>
  )
}

// Rocket with trail - Launch/Start
export function IconRocketLaunch({ className = 'w-6 h-6', strokeWidth = 1.5 }: IconProps) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
      <path
        d="M12 2C12 2 8 6 8 12C8 14 8.5 15.5 9 17L12 15L15 17C15.5 15.5 16 14 16 12C16 6 12 2 12 2Z"
        stroke="currentColor"
        strokeWidth={strokeWidth}
        strokeLinecap="round"
        strokeLinejoin="round"
      />
      <circle cx="12" cy="10" r="2" stroke="currentColor" strokeWidth={strokeWidth}/>
      <path d="M5 17L8 14" stroke="currentColor" strokeWidth={strokeWidth} strokeLinecap="round"/>
      <path d="M19 17L16 14" stroke="currentColor" strokeWidth={strokeWidth} strokeLinecap="round"/>
      <path d="M9 22L12 18L15 22" stroke="currentColor" strokeWidth={strokeWidth} strokeLinecap="round" strokeLinejoin="round"/>
    </svg>
  )
}

// Sparkle/AI magic
export function IconSparkle({ className = 'w-6 h-6', strokeWidth = 1.5 }: IconProps) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
      <path
        d="M12 2L13.5 8.5L20 10L13.5 11.5L12 18L10.5 11.5L4 10L10.5 8.5L12 2Z"
        stroke="currentColor"
        strokeWidth={strokeWidth}
        strokeLinecap="round"
        strokeLinejoin="round"
        fill="currentColor"
        fillOpacity="0.15"
      />
      <path d="M18 16L19 19L22 20L19 21L18 24L17 21L14 20L17 19L18 16Z" stroke="currentColor" strokeWidth="1" strokeLinecap="round" strokeLinejoin="round" fill="currentColor" fillOpacity="0.1"/>
    </svg>
  )
}

// Arrow right stylized
export function IconArrowRight({ className = 'w-6 h-6', strokeWidth = 1.5 }: IconProps) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
      <path
        d="M5 12H19M19 12L13 6M19 12L13 18"
        stroke="currentColor"
        strokeWidth={strokeWidth}
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  )
}

// Lock with keyhole - Security/Auth
export function IconLockSecure({ className = 'w-6 h-6', strokeWidth = 1.5 }: IconProps) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
      <rect x="4" y="10" width="16" height="11" rx="2" stroke="currentColor" strokeWidth={strokeWidth}/>
      <path d="M8 10V7C8 4.79 9.79 3 12 3C14.21 3 16 4.79 16 7V10" stroke="currentColor" strokeWidth={strokeWidth} strokeLinecap="round"/>
      <circle cx="12" cy="15" r="1.5" fill="currentColor"/>
      <path d="M12 16.5V18" stroke="currentColor" strokeWidth={strokeWidth} strokeLinecap="round"/>
    </svg>
  )
}

// Report/Document with checkmarks
export function IconReport({ className = 'w-6 h-6', strokeWidth = 1.5 }: IconProps) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
      <path d="M14 2H6C5.46957 2 4.96086 2.21071 4.58579 2.58579C4.21071 2.96086 4 3.46957 4 4V20C4 20.5304 4.21071 21.0391 4.58579 21.4142C4.96086 21.7893 5.46957 22 6 22H18C18.5304 22 19.0391 21.7893 19.4142 21.4142C19.7893 21.0391 20 20.5304 20 20V8L14 2Z" stroke="currentColor" strokeWidth={strokeWidth} strokeLinecap="round" strokeLinejoin="round"/>
      <path d="M14 2V8H20" stroke="currentColor" strokeWidth={strokeWidth} strokeLinecap="round" strokeLinejoin="round"/>
      <path d="M8 13L10 15L14 11" stroke="currentColor" strokeWidth={strokeWidth} strokeLinecap="round" strokeLinejoin="round"/>
      <path d="M8 18H16" stroke="currentColor" strokeWidth={strokeWidth} strokeLinecap="round" opacity="0.5"/>
    </svg>
  )
}
