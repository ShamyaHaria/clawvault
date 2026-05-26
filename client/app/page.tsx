import Link from 'next/link'
import { CheckCircle, XCircle, AlertTriangle, ArrowRight, Shield, Lock, Search, Zap } from 'lucide-react'
import { getSkills } from '@/lib/api'

function RiskBadge({ level, passed }: { level: string; passed: boolean }) {
  if (passed) return (
    <span style={{
      display: 'inline-flex', alignItems: 'center', gap: '4px',
      fontSize: '11px', fontWeight: 600, letterSpacing: '0.04em',
      color: 'var(--accent-green)', background: 'rgba(63,185,80,0.1)',
      border: '1px solid rgba(63,185,80,0.3)', padding: '2px 8px', borderRadius: '20px',
    }}>
      <CheckCircle size={10} /> VERIFIED
    </span>
  )
  if (level === 'critical') return (
    <span style={{
      display: 'inline-flex', alignItems: 'center', gap: '4px',
      fontSize: '11px', fontWeight: 600, letterSpacing: '0.04em',
      color: 'var(--accent-red)', background: 'rgba(248,81,73,0.1)',
      border: '1px solid rgba(248,81,73,0.3)', padding: '2px 8px', borderRadius: '20px',
    }}>
      <XCircle size={10} /> CRITICAL
    </span>
  )
  return (
    <span style={{
      display: 'inline-flex', alignItems: 'center', gap: '4px',
      fontSize: '11px', fontWeight: 600, letterSpacing: '0.04em',
      color: 'var(--accent-orange)', background: 'rgba(210,153,34,0.1)',
      border: '1px solid rgba(210,153,34,0.3)', padding: '2px 8px', borderRadius: '20px',
    }}>
      <AlertTriangle size={10} /> {level.toUpperCase()}
    </span>
  )
}

export default async function HomePage() {
  let skills: Awaited<ReturnType<typeof getSkills>> = []
  try { skills = await getSkills() } catch { skills = [] }

  const verified = skills.filter(s => s.reports?.[0]?.passed).length

  return (
    <div>
      {/* Hero */}
      <div style={{
        textAlign: 'center',
        padding: '72px 0 64px',
        borderBottom: '1px solid var(--border-subtle)',
        marginBottom: '56px',
        position: 'relative',
      }}>
        <div style={{
          position: 'absolute', inset: 0,
          background: 'radial-gradient(ellipse 80% 50% at 50% -20%, rgba(47,129,247,0.08), transparent)',
          pointerEvents: 'none',
        }} />
        <div style={{
          display: 'inline-flex', alignItems: 'center', gap: '6px',
          fontSize: '12px', fontWeight: 500, color: 'var(--accent-blue)',
          background: 'rgba(47,129,247,0.1)', border: '1px solid rgba(47,129,247,0.25)',
          padding: '4px 12px', borderRadius: '20px', marginBottom: '24px',
          letterSpacing: '0.04em',
        }}>
          <Shield size={11} /> SECURITY INFRASTRUCTURE FOR OPENCLAW
        </div>

        <h1 style={{
          fontFamily: 'Syne, sans-serif',
          fontSize: '52px', fontWeight: 800,
          color: 'var(--text-primary)',
          lineHeight: 1.1, letterSpacing: '-0.03em',
          marginBottom: '20px',
        }}>
          The trusted skill registry<br />
          <span style={{ color: 'var(--accent-blue)' }}>for OpenClaw</span>
        </h1>

        <p style={{
          fontSize: '17px', color: 'var(--text-secondary)',
          maxWidth: '520px', margin: '0 auto 36px',
          lineHeight: 1.6, fontWeight: 300,
        }}>
          Every skill audited before it goes live. Know exactly what a skill does,
          what permissions it requests, and whether it is safe to install.
        </p>

        <div style={{ display: 'flex', justifyContent: 'center', gap: '12px', marginBottom: '56px' }}>
          <Link href="/submit" style={{
            display: 'inline-flex', alignItems: 'center', gap: '8px',
            backgroundColor: 'var(--accent-blue)', color: '#fff',
            padding: '10px 22px', borderRadius: '8px',
            fontWeight: 500, fontSize: '14px', textDecoration: 'none',
          }}>
            Submit a Skill <ArrowRight size={15} />
          </Link>
          <a href="#directory" style={{
            display: 'inline-flex', alignItems: 'center',
            border: '1px solid var(--border-default)', color: 'var(--text-secondary)',
            padding: '10px 22px', borderRadius: '8px',
            fontWeight: 500, fontSize: '14px', textDecoration: 'none',
          }}>
            Browse Directory
          </a>
        </div>

        {/* Stats */}
        <div style={{ display: 'flex', justifyContent: 'center', gap: '48px' }}>
          {[
            { value: skills.length, label: 'Skills audited' },
            { value: verified, label: 'Verified safe' },
            { value: '4', label: 'Audit layers' },
            { value: '110', label: 'Security tests' },
          ].map(({ value, label }) => (
            <div key={label}>
              <div style={{
                fontFamily: 'Syne, sans-serif',
                fontSize: '28px', fontWeight: 700,
                color: 'var(--text-primary)', lineHeight: 1,
              }}>{value}</div>
              <div style={{ fontSize: '12px', color: 'var(--text-muted)', marginTop: '6px' }}>{label}</div>
            </div>
          ))}
        </div>
      </div>

      {/* How it works */}
      <div style={{ marginBottom: '56px' }}>
        <h2 style={{
          fontFamily: 'Syne, sans-serif', fontSize: '13px', fontWeight: 600,
          color: 'var(--text-muted)', letterSpacing: '0.08em',
          textTransform: 'uppercase', marginBottom: '24px',
        }}>
          How it works
        </h2>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '12px' }}>
          {[
            { icon: <Lock size={16} />, title: 'Credential Scan', desc: 'Detects hardcoded API keys, tokens, and private keys' },
            { icon: <Search size={16} />, title: 'Obfuscation Check', desc: 'Catches eval chains, base64 payloads, and dynamic imports' },
            { icon: <Shield size={16} />, title: 'Permission Audit', desc: 'Verifies behavior matches declared SKILL.md permissions' },
            { icon: <Zap size={16} />, title: 'Typosquat Detection', desc: 'Flags names engineered to impersonate known skills' },
          ].map(({ icon, title, desc }) => (
            <div key={title} style={{
              background: 'var(--bg-surface)',
              border: '1px solid var(--border-subtle)',
              borderRadius: '10px', padding: '20px',
            }}>
              <div style={{
                color: 'var(--accent-blue)', marginBottom: '10px',
                display: 'flex', alignItems: 'center',
              }}>{icon}</div>
              <div style={{
                fontFamily: 'Syne, sans-serif',
                fontSize: '13px', fontWeight: 600,
                color: 'var(--text-primary)', marginBottom: '6px',
              }}>{title}</div>
              <div style={{ fontSize: '12px', color: 'var(--text-secondary)', lineHeight: 1.5 }}>{desc}</div>
            </div>
          ))}
        </div>
      </div>

      {/* Directory */}
      <div id="directory">
        <div style={{
          display: 'flex', alignItems: 'center',
          justifyContent: 'space-between', marginBottom: '16px',
        }}>
          <h2 style={{
            fontFamily: 'Syne, sans-serif', fontSize: '13px', fontWeight: 600,
            color: 'var(--text-muted)', letterSpacing: '0.08em', textTransform: 'uppercase',
          }}>
            Skill Directory
          </h2>
          <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>{skills.length} skills</span>
        </div>

        {skills.length === 0 ? (
          <div style={{
            textAlign: 'center', padding: '64px 20px',
            border: '1px dashed var(--border-subtle)', borderRadius: '12px',
          }}>
            <Shield size={24} color="var(--text-muted)" style={{ margin: '0 auto 12px' }} />
            <p style={{ color: 'var(--text-secondary)', fontSize: '14px' }}>No skills audited yet.</p>
            <Link href="/submit" style={{
              color: 'var(--accent-blue)', fontSize: '13px',
              textDecoration: 'none', display: 'inline-block', marginTop: '8px',
            }}>Submit the first one →</Link>
          </div>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
            {skills.map((skill) => {
              const report = skill.reports?.[0]
              return (
                <Link key={skill.id} href={`/skills/${skill.id}`} style={{
                  display: 'flex', alignItems: 'center',
                  justifyContent: 'space-between',
                  padding: '16px 20px',
                  background: 'var(--bg-surface)',
                  border: '1px solid var(--border-subtle)',
                  borderRadius: '10px', textDecoration: 'none',
                  transition: 'border-color 0.15s',
                }}>
                  <div>
                    <div style={{
                      display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '4px',
                    }}>
                      <span style={{
                        fontFamily: 'Syne, sans-serif',
                        fontWeight: 600, fontSize: '14px', color: 'var(--text-primary)',
                      }}>{skill.name}</span>
                      {report && <RiskBadge level={report.riskLevel} passed={report.passed} />}
                    </div>
                    <p style={{ fontSize: '13px', color: 'var(--text-secondary)' }}>{skill.description}</p>
                    <p style={{ fontSize: '12px', color: 'var(--text-muted)', marginTop: '4px' }}>by {skill.author}</p>
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
                    {report && (
                      <div style={{ textAlign: 'right' }}>
                        <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>Risk Score</div>
                        <div style={{
                          fontFamily: 'Syne, sans-serif',
                          fontSize: '18px', fontWeight: 700, color: 'var(--text-primary)',
                        }}>{report.riskScore}</div>
                      </div>
                    )}
                    <ArrowRight size={16} color="var(--text-muted)" />
                  </div>
                </Link>
              )
            })}
          </div>
        )}
      </div>
    </div>
  )
}