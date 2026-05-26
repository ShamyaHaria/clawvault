'use client'

import { useState } from 'react'
import { Shield, Upload, CheckCircle, AlertCircle, Loader2, ArrowLeft } from 'lucide-react'
import Link from 'next/link'

const API_BASE = process.env.NEXT_PUBLIC_API_URL ?? 'http://localhost:3001'
type Status = 'idle' | 'submitting' | 'success' | 'error'

const inputStyle = {
  width: '100%',
  background: 'var(--bg-surface)',
  border: '1px solid var(--border-default)',
  borderRadius: '8px',
  padding: '10px 14px',
  fontSize: '13px',
  color: 'var(--text-primary)',
  outline: 'none',
  fontFamily: 'DM Sans, sans-serif',
}

export default function SubmitPage() {
  const [status, setStatus] = useState<Status>('idle')
  const [submissionId, setSubmissionId] = useState('')
  const [error, setError] = useState('')
  const [file, setFile] = useState<File | null>(null)

  async function handleSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault()
    setStatus('submitting')
    setError('')
    const data = new FormData(e.currentTarget)
    if (file) data.set('skill', file)
    try {
      const res = await fetch(`${API_BASE}/api/submissions`, { method: 'POST', body: data })
      if (!res.ok) {
        const err = await res.json()
        throw new Error(err.error ?? 'Submission failed')
      }
      const result = await res.json()
      setSubmissionId(result.submissionId)
      setStatus('success')
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Something went wrong')
      setStatus('error')
    }
  }

  if (status === 'success') {
    return (
      <div style={{ maxWidth: '480px', margin: '0 auto', textAlign: 'center', paddingTop: '64px' }}>
        <CheckCircle size={40} color="var(--accent-green)" style={{ margin: '0 auto 16px' }} />
        <h1 style={{
          fontFamily: 'Syne, sans-serif', fontSize: '22px', fontWeight: 700,
          color: 'var(--text-primary)', marginBottom: '8px',
        }}>Submission received</h1>
        <p style={{ fontSize: '14px', color: 'var(--text-secondary)', marginBottom: '24px', lineHeight: 1.6 }}>
          Your skill is being audited across all 4 layers. This usually takes under a minute.
        </p>
        <div style={{
          background: 'var(--bg-surface)', border: '1px solid var(--border-subtle)',
          borderRadius: '10px', padding: '16px', marginBottom: '24px', textAlign: 'left',
        }}>
          <p style={{ fontSize: '11px', color: 'var(--text-muted)', marginBottom: '6px', letterSpacing: '0.04em' }}>
            SUBMISSION ID
          </p>
          <p style={{ fontFamily: 'monospace', fontSize: '13px', color: 'var(--text-secondary)', wordBreak: 'break-all' }}>
            {submissionId}
          </p>
        </div>
        <div style={{ display: 'flex', gap: '10px', justifyContent: 'center' }}>
          <Link href="/" style={{
            border: '1px solid var(--border-default)', color: 'var(--text-secondary)',
            padding: '9px 18px', borderRadius: '8px', fontSize: '13px',
            fontWeight: 500, textDecoration: 'none',
          }}>Back to directory</Link>
          <button onClick={() => { setStatus('idle'); setFile(null) }} style={{
            background: 'var(--accent-blue)', color: '#fff',
            padding: '9px 18px', borderRadius: '8px', fontSize: '13px',
            fontWeight: 500, border: 'none', cursor: 'pointer',
          }}>Submit another</button>
        </div>
      </div>
    )
  }

  return (
    <div style={{ maxWidth: '520px', margin: '0 auto' }}>
      <Link href="/" style={{
        display: 'inline-flex', alignItems: 'center', gap: '6px',
        fontSize: '13px', color: 'var(--text-secondary)',
        textDecoration: 'none', marginBottom: '32px',
      }}>
        <ArrowLeft size={14} /> Back
      </Link>

      <div style={{ marginBottom: '28px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '8px' }}>
          <Shield size={16} color="var(--accent-blue)" />
          <h1 style={{
            fontFamily: 'Syne, sans-serif', fontSize: '20px',
            fontWeight: 700, color: 'var(--text-primary)',
          }}>Submit a skill for audit</h1>
        </div>
        <p style={{ fontSize: '13px', color: 'var(--text-secondary)', lineHeight: 1.6 }}>
          Upload your OpenClaw skill as a ZIP file. We&apos;ll run it through our 4-layer
          audit pipeline and publish the results publicly.
        </p>
      </div>

      <form onSubmit={handleSubmit}>
        <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
          {[
            { name: 'name', label: 'Skill name', placeholder: 'e.g. file-reader', type: 'text' },
            { name: 'author', label: 'Author', placeholder: 'Your name or organization', type: 'text' },
            { name: 'repositoryUrl', label: 'Repository URL', placeholder: 'https://github.com/you/your-skill', type: 'url' },
          ].map(({ name, label, placeholder, type }) => (
            <div key={name}>
              <label style={{
                display: 'block', fontSize: '12px', fontWeight: 500,
                color: 'var(--text-secondary)', marginBottom: '6px', letterSpacing: '0.02em',
              }}>{label}</label>
              <input name={name} required type={type} placeholder={placeholder} style={inputStyle} />
            </div>
          ))}

          <div>
            <label style={{
              display: 'block', fontSize: '12px', fontWeight: 500,
              color: 'var(--text-secondary)', marginBottom: '6px',
            }}>Description</label>
            <textarea name="description" required rows={3} placeholder="What does this skill do?" style={{
              ...inputStyle, resize: 'none', lineHeight: 1.5,
            }} />
          </div>

          <div>
            <label style={{
              display: 'block', fontSize: '12px', fontWeight: 500,
              color: 'var(--text-secondary)', marginBottom: '6px',
            }}>Skill ZIP file</label>
            <label style={{
              display: 'flex', flexDirection: 'column', alignItems: 'center',
              justifyContent: 'center', width: '100%',
              border: `1px dashed ${file ? 'var(--accent-blue)' : 'var(--border-default)'}`,
              borderRadius: '10px', padding: '32px 20px', cursor: 'pointer',
              background: file ? 'rgba(47,129,247,0.04)' : 'var(--bg-surface)',
              transition: 'all 0.15s',
            }}>
              <Upload size={20} color={file ? 'var(--accent-blue)' : 'var(--text-muted)'} style={{ marginBottom: '8px' }} />
              {file
                ? <span style={{ fontSize: '13px', color: 'var(--accent-blue)', fontWeight: 500 }}>{file.name}</span>
                : <>
                    <span style={{ fontSize: '13px', color: 'var(--text-secondary)' }}>Click to upload ZIP</span>
                    <span style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: '4px' }}>Max 50MB</span>
                  </>
              }
              <input type="file" accept=".zip" style={{ display: 'none' }}
                onChange={(e) => setFile(e.target.files?.[0] ?? null)} />
            </label>
          </div>

          {status === 'error' && (
            <div style={{
              display: 'flex', alignItems: 'center', gap: '8px',
              color: 'var(--accent-red)', background: 'rgba(248,81,73,0.08)',
              border: '1px solid rgba(248,81,73,0.25)',
              borderRadius: '8px', padding: '12px 14px', fontSize: '13px',
            }}>
              <AlertCircle size={15} style={{ flexShrink: 0 }} />
              {error}
            </div>
          )}

          <button type="submit" disabled={status === 'submitting' || !file} style={{
            width: '100%', background: 'var(--accent-blue)', color: '#fff',
            padding: '11px', borderRadius: '8px', fontSize: '13px',
            fontWeight: 600, border: 'none', cursor: 'pointer',
            opacity: status === 'submitting' || !file ? 0.5 : 1,
            display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '8px',
            fontFamily: 'Syne, sans-serif', letterSpacing: '0.02em',
          }}>
            {status === 'submitting'
              ? <><Loader2 size={15} /> Submitting...</>
              : 'Submit for Audit'
            }
          </button>

          <p style={{ fontSize: '11px', color: 'var(--text-muted)', textAlign: 'center', lineHeight: 1.5 }}>
            By submitting you agree that your skill will be publicly audited and the results published on ClawVault.
          </p>
        </div>
      </form>
    </div>
  )
}