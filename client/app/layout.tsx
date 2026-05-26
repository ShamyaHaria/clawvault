import type { Metadata } from 'next'
import './globals.css'
import Link from 'next/link'
import { Shield } from 'lucide-react'

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
          backgroundColor: 'var(--bg-base)',
          position: 'sticky',
          top: 0,
          zIndex: 50,
        }}>
          <div style={{
            maxWidth: '1100px',
            margin: '0 auto',
            padding: '0 24px',
            height: '56px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
          }}>
            <Link href="/" style={{
              display: 'flex',
              alignItems: 'center',
              gap: '8px',
              fontFamily: 'Syne, sans-serif',
              fontWeight: 700,
              fontSize: '16px',
              color: 'var(--text-primary)',
              textDecoration: 'none',
              letterSpacing: '-0.02em',
            }}>
              <Shield size={18} color="var(--accent-blue)" />
              ClawVault
            </Link>
            <div style={{ display: 'flex', alignItems: 'center', gap: '24px' }}>
              <Link href="/" style={{
                fontSize: '13px',
                color: 'var(--text-secondary)',
                textDecoration: 'none',
              }}>Directory</Link>
              <Link href="/submit" style={{
                fontSize: '13px',
                color: 'var(--text-secondary)',
                textDecoration: 'none',
              }}>Submit</Link>
              <Link href="/submit" style={{
                fontSize: '13px',
                fontWeight: 500,
                color: '#fff',
                backgroundColor: 'var(--accent-blue)',
                padding: '6px 14px',
                borderRadius: '6px',
                textDecoration: 'none',
              }}>
                Get Verified
              </Link>
            </div>
          </div>
        </nav>
        <main style={{ maxWidth: '1100px', margin: '0 auto', padding: '40px 24px' }}>
          {children}
        </main>
      </body>
    </html>
  )
}