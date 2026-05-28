import type { Metadata } from 'next'
import './globals.css'
import Link from 'next/link'

export const metadata: Metadata = {
  title: 'ClawVault — Trusted Skill Registry for OpenClaw',
  description: 'Every skill audited before it goes live. No backdoors. No surprises.',
}

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>
        <nav style={{
          borderBottom: '1px solid var(--border-subtle)',
          backgroundColor: 'rgba(8,12,16,0.92)',
          backdropFilter: 'blur(12px)',
          position: 'sticky',
          top: 0,
          zIndex: 50,
        }}>
          <div style={{
            maxWidth: '1100px',
            margin: '0 auto',
            padding: '0 24px',
            height: '52px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
          }}>
            <Link href="/" style={{
              display: 'flex',
              alignItems: 'center',
              gap: '10px',
              textDecoration: 'none',
            }}>
              <div style={{
                width: '28px',
                height: '28px',
                background: 'linear-gradient(135deg, #1e3a5f, #3b82f6)',
                borderRadius: '6px',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                fontSize: '14px',
                fontFamily: 'var(--mono)',
                fontWeight: 600,
                color: '#fff',
                boxShadow: '0 0 12px rgba(59,130,246,0.3)',
              }}>CV</div>
              <span style={{
                fontFamily: 'var(--mono)',
                fontWeight: 600,
                fontSize: '15px',
                color: 'var(--text-primary)',
                letterSpacing: '-0.02em',
              }}>ClawVault</span>
            </Link>

            <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
              <Link href="/" style={{
                fontSize: '13px',
                color: 'var(--text-secondary)',
                textDecoration: 'none',
                padding: '6px 12px',
                borderRadius: '6px',
                fontWeight: 500,
              }}>Directory</Link>
              <Link href="/submit" style={{
                fontSize: '13px',
                color: 'var(--text-secondary)',
                textDecoration: 'none',
                padding: '6px 12px',
                borderRadius: '6px',
                fontWeight: 500,
              }}>Submit</Link>
              <Link href="/submit" style={{
                fontSize: '13px',
                fontWeight: 600,
                color: '#fff',
                backgroundColor: 'var(--accent-blue)',
                padding: '6px 16px',
                borderRadius: '6px',
                textDecoration: 'none',
                letterSpacing: '0.01em',
                boxShadow: '0 0 16px rgba(59,130,246,0.25)',
              }}>
                Get Verified
              </Link>
            </div>
          </div>
        </nav>
        <main style={{ maxWidth: '1100px', margin: '0 auto', padding: '48px 24px' }}>
          {children}
        </main>
      </body>
    </html>
  )
}