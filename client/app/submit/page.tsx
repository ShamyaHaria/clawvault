'use client'

import { useState } from 'react'
import Link from 'next/link'

const API_BASE = process.env.NEXT_PUBLIC_API_URL ?? 'http://localhost:3001'
type Status = 'idle' | 'submitting' | 'success' | 'error'

const inputStyle: React.CSSProperties = {
  width: '100%',
  background: 'var(--bg-surface)',
  border: '1px solid var(--border-default)',
  borderRadius: '7px',
  padding: '10px 14px',
  fontSize: '14px',
  color: 'var(--text-primary)',
  outline: 'none',
  fontFamily: 'var(--sans)',
}

const labelStyle: React.CSSProperties = {
  display: 'block',
  fontFamily: 'var(--mono)',
  fontSize: '11px',
  fontWeight: 500,
  color: 'var(--text-muted)',
  marginBottom: '7px',
  letterSpacing: '0.06em',
  textTransform: 'uppercase',
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
      <div style={{ maxWidth: '480px', margin: '0 auto', paddingTop: '40px' }}>
        <div style={{
          background: 'var(--bg-surface)',
          border: '1px solid rgba(34,197,94,0.2)',
          borderRadius: '10px', padding: '32px',
          textAlign: 'center',
          boxShadow: '0 0 30px rgba(34,197,94,0.05)',
        }}>
          <div style={{
            fontFamily: 'var(--mono)', fontSize: '32px',
            color: 'var(--accent-green)', marginBottom: '12px',
          }}>✓</div>
          <div style={{
            fontFamily: 'var(--mono)', fontSize: '16px',
            fontWeight: 600, color: 'var(--text-primary)',
            marginBottom: '8px',
          }}>submission received</div>
          <div style={{
            fontSize: '13px', color: 'var(--text-secondary)',
            marginBottom: '24px', lineHeight: 1.6,
          }}>
            Auditing across all 7 layers. Results publish in seconds.
          </div>
          <div style={{
            background: 'var(--bg-base)',
            border: '1px solid var(--border-subtle)',
            borderRadius: '7px', padding: '12px 16px',
            marginBottom: '24px', textAlign: 'left',
          }}>
            <div style={{
              fontFamily: 'var(--mono)', fontSize: '10px',
              color: 'var(--text-muted)', letterSpacing: '0.08em',
              textTransform: 'uppercase', marginBottom: '6px',
            }}>submission_id</div>
            <div style={{
              fontFamily: 'var(--mono)', fontSize: '12px',
              color: 'var(--text-secondary)', wordBreak: 'break-all',
            }}>{submissionId}</div>
          </div>
          <div style={{ display: 'flex', gap: '8px', justifyContent: 'center' }}>
            <Link href="/" style={{
              border: '1px solid var(--border-default)',
              color: 'var(--text-secondary)',
              padding: '8px 18px', borderRadius: '7px',
              fontSize: '13px', fontWeight: 500,
              textDecoration: 'none', fontFamily: 'var(--mono)',
            }}>← directory</Link>
            <button onClick={() => { setStatus('idle'); setFile(null) }} style={{
              background: 'var(--accent-blue)', color: '#fff',
              padding: '8px 18px', borderRadius: '7px',
              fontSize: '13px', fontWeight: 600,
              border: 'none', cursor: 'pointer',
              fontFamily: 'var(--mono)',
            }}>submit another</button>
          </div>
        </div>
      </div>
    )
  }

  return (
    <div style={{ maxWidth: '520px', margin: '0 auto' }}>
      <Link href="/" style={{
        fontFamily: 'var(--mono)', fontSize: '12px',
        color: 'var(--text-muted)', textDecoration: 'none',
        display: 'inline-block', marginBottom: '28px',
      }}>← directory</Link>

      <div style={{ marginBottom: '28px' }}>
        <div style={{
          fontFamily: 'var(--mono)', fontSize: '11px',
          color: 'var(--text-muted)', letterSpacing: '0.1em',
          textTransform: 'uppercase', marginBottom: '8px',
        }}>Submit for audit</div>
        <div style={{
          fontFamily: 'var(--mono)', fontSize: '20px',
          fontWeight: 600, color: 'var(--text-primary)',
          marginBottom: '8px',
        }}>Get your skill verified</div>
        <div style={{
          fontSize: '14px', color: 'var(--text-secondary)',
          lineHeight: 1.6, fontWeight: 300,
        }}>
          Upload your OpenClaw skill as a ZIP. We&apos;ll run it through 7 audit
          layers and publish the results publicly within seconds.
        </div>
      </div>

      <form onSubmit={handleSubmit}>
        <div style={{ display: 'flex', flexDirection: 'column', gap: '18px' }}>
          {[
            { name: 'name', label: 'skill_name', placeholder: 'e.g. weather-fetcher', type: 'text' },
            { name: 'author', label: 'author', placeholder: 'your name or org', type: 'text' },
            { name: 'repositoryUrl', label: 'repository_url', placeholder: 'https://github.com/you/skill', type: 'url' },
          ].map(({ name, label, placeholder, type }) => (
            <div key={name}>
              <label style={labelStyle}>{label}</label>
              <input
                name={name} required type={type}
                placeholder={placeholder}
                style={inputStyle}
              />
            </div>
          ))}

          <div>
            <label style={labelStyle}>description</label>
            <textarea
              name="description" required rows={3}
              placeholder="what does this skill do?"
              style={{ ...inputStyle, resize: 'none', lineHeight: 1.6 }}
            />
          </div>

          <div>
            <label style={labelStyle}>skill_zip</label>
            <label style={{
              display: 'flex', flexDirection: 'column',
              alignItems: 'center', justifyContent: 'center',
              width: '100%', padding: '28px 20px',
              border: `1px dashed ${file ? 'var(--accent-blue)' : 'var(--border-default)'}`,
              borderRadius: '8px', cursor: 'pointer',
              background: file ? 'var(--accent-blue-dim)' : 'var(--bg-surface)',
              transition: 'all 0.15s',
            }}>
              {file ? (
                <div style={{
                  fontFamily: 'var(--mono)', fontSize: '13px',
                  color: 'var(--accent-blue)',
                }}>{file.name}</div>
              ) : (
                <>
                  <div style={{
                    fontFamily: 'var(--mono)', fontSize: '20px',
                    color: 'var(--text-muted)', marginBottom: '6px',
                  }}>↑</div>
                  <div style={{
                    fontFamily: 'var(--mono)', fontSize: '12px',
                    color: 'var(--text-secondary)',
                  }}>click to upload .zip</div>
                  <div style={{
                    fontFamily: 'var(--mono)', fontSize: '11px',
                    color: 'var(--text-muted)', marginTop: '4px',
                  }}>max 50mb</div>
                </>
              )}
              <input
                type="file" accept=".zip"
                style={{ display: 'none' }}
                onChange={(e) => setFile(e.target.files?.[0] ?? null)}
              />
            </label>
          </div>

          {status === 'error' && (
            <div style={{
              display: 'flex', alignItems: 'center', gap: '8px',
              color: 'var(--accent-red)',
              background: 'var(--accent-red-dim)',
              border: '1px solid rgba(239,68,68,0.2)',
              borderRadius: '7px', padding: '10px 14px',
              fontFamily: 'var(--mono)', fontSize: '12px',
            }}>
              ✗ {error}
            </div>
          )}

          <button
            type="submit"
            disabled={status === 'submitting' || !file}
            style={{
              width: '100%',
              background: status === 'submitting' || !file
                ? 'var(--bg-elevated)'
                : 'var(--accent-blue)',
              color: status === 'submitting' || !file
                ? 'var(--text-muted)'
                : '#fff',
              padding: '12px',
              borderRadius: '7px',
              fontSize: '14px', fontWeight: 600,
              border: `1px solid ${status === 'submitting' || !file ? 'var(--border-default)' : 'transparent'}`,
              cursor: status === 'submitting' || !file ? 'not-allowed' : 'pointer',
              fontFamily: 'var(--mono)',
              letterSpacing: '0.04em',
              transition: 'all 0.15s',
            }}
          >
            {status === 'submitting' ? 'auditing...' : 'submit_for_audit()'}
          </button>

          <div style={{
            fontFamily: 'var(--mono)', fontSize: '11px',
            color: 'var(--text-muted)', textAlign: 'center',
            lineHeight: 1.6,
          }}>
            // results published publicly. all findings disclosed.
          </div>
        </div>
      </form>
    </div>
  )
}