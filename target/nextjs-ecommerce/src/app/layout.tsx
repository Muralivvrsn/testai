import './globals.css'
import type { Metadata } from 'next'

export const metadata: Metadata = {
  title: 'ShopFlow - Modern E-commerce',
  description: 'Complex E-commerce target for QA testing',
}

export default function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  )
}
