import Link from 'next/link'
import { getSkills } from '@/lib/api'

function RiskBadge({ level, passed }: { level: string; passed: boolean }) {
  if (passed) return (
    <span style={{
      display: 'inline-flex', alignItems: 'center', gap: '5px',
      fontSize: '10px', fontWeight: 600, letterSpacing: '0.08em',
      fontFamily: 'var(--mono)',
      color: 'var(--accent-green)',
      background: 'var(--accent-green-dim)',
      border: '1px solid rgba(34,197,94,0.25)',
      padding: '3px 8px', borderRadius: '4px',
      boxShadow: '0 0 8px rgba(34,197,94,0.1)',
    }}>
      ● VERIFIED
    </span>
  )
  const map: Record<string, { color: string; bg: string; border: string }> = {
    critical: { color: 'var(--accent-red)', bg: 'var(--accent-red-dim)', border: 'rgba(239,68,68,0.25)' },
    high:     { color: 'var(--accent-orange)', bg: 'rgba(245,158,11,0.08)', border: 'rgba(245,158,11,0.25)' },
    medium:   { color: 'var(--accent-yellow)', bg: 'rgba(234,179,8,0.08)', border: 'rgba(234,179,8,0.25)' },
    low:      { color: 'var(--text-secondary)', bg: 'var(--bg-elevated)', border: 'var(--border-default)' },
  }
  const s = map[level] ?? map.low
  return (
    <span style={{
      display: 'inline-flex', alignItems: 'center', gap: '5px',
      fontSize: '10px', fontWeight: 600, letterSpacing: '0.08em',
      fontFamily: 'var(--mono)',
      color: s.color, background: s.bg,
      border: `1px solid ${s.border}`,
      padding: '3px 8px', borderRadius: '4px',
    }}>
      ● {level.toUpperCase()}
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
        paddingBottom: '64px',
        borderBottom: '1px solid var(--border-subtle)',
        marginBottom: '48px',
        position: 'relative',
      }}>
        <div style={{
          position: 'absolute', inset: 0,
          background: 'radial-gradient(ellipse 60% 40% at 50% 0%, rgba(59,130,246,0.06), transparent)',
          pointerEvents: 'none',
        }} />

        <div style={{ marginBottom: '20px' }}>
          <span style={{
            fontFamily: 'var(--mono)',
            fontSize: '11px', fontWeight: 500,
            color: 'var(--text-muted)',
            letterSpacing: '0.1em',
          }}>
            SECURITY INFRASTRUCTURE / OPENCLAW ECOSYSTEM
          </span>
        </div>

        <h1 style={{
          fontFamily: 'var(--mono)',
          fontSize: '48px', fontWeight: 600,
          color: 'var(--text-primary)',
          lineHeight: 1.1, letterSpacing: '-0.03em',
          marginBottom: '20px',
          maxWidth: '700px',
        }}>
          Every skill.<br />
          <span style={{ color: 'var(--accent-blue)' }}>Audited.</span>{' '}
          <span style={{ color: 'var(--text-secondary)', fontWeight: 400 }}>Verified.</span>{' '}
          Trusted.
        </h1>

        <p style={{
          fontSize: '16px', color: 'var(--text-secondary)',
          maxWidth: '560px', lineHeight: 1.7,
          marginBottom: '36px', fontWeight: 300,
        }}>
          ClawVault audits every OpenClaw skill through a 7-layer static analysis
          pipeline before issuing a public trust verdict. No backdoors. No surprises.
        </p>

        <div style={{ display: 'flex', gap: '10px', marginBottom: '56px', flexWrap: 'wrap' }}>
          <Link href="/submit" style={{
            display: 'inline-flex', alignItems: 'center', gap: '8px',
            backgroundColor: 'var(--accent-blue)',
            color: '#fff', padding: '10px 24px',
            borderRadius: '7px', fontWeight: 600,
            fontSize: '14px', textDecoration: 'none',
            fontFamily: 'var(--sans)',
            boxShadow: '0 0 24px rgba(59,130,246,0.3)',
            letterSpacing: '0.01em',
          }}>
            Submit for Audit →
          </Link>
          <a href="#directory" style={{
            display: 'inline-flex', alignItems: 'center',
            border: '1px solid var(--border-default)',
            color: 'var(--text-secondary)',
            padding: '10px 24px', borderRadius: '7px',
            fontWeight: 500, fontSize: '14px',
            textDecoration: 'none',
          }}>
            Browse Directory
          </a>
        </div>

        {/* Stats row */}
        <div style={{ display: 'flex', gap: '40px', flexWrap: 'wrap' }}>
          {[
            { value: skills.length, label: 'skills audited', mono: true },
            { value: verified, label: 'verified safe', mono: true },
            { value: '7', label: 'detector layers', mono: true },
            { value: '243', label: 'security tests', mono: true },
          ].map(({ value, label }) => (
            <div key={label}>
              <div style={{
                fontFamily: 'var(--mono)',
                fontSize: '32px', fontWeight: 600,
                color: 'var(--text-primary)',
                lineHeight: 1, letterSpacing: '-0.03em',
              }}>{value}</div>
              <div style={{
                fontSize: '12px', color: 'var(--text-muted)',
                marginTop: '6px', fontWeight: 400,
                letterSpacing: '0.04em', textTransform: 'uppercase',
              }}>{label}</div>
            </div>
          ))}
        </div>
      </div>

      {/* Detector layers */}
      <div style={{ marginBottom: '56px' }}>
        <div style={{
          fontFamily: 'var(--mono)', fontSize: '11px',
          fontWeight: 500, color: 'var(--text-muted)',
          letterSpacing: '0.1em', textTransform: 'uppercase',
          marginBottom: '16px',
        }}>Audit Pipeline</div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '8px' }}>
          {[
            { id: '01', name: 'Credential Scan', desc: '15+ token types detected' },
            { id: '02', name: 'Obfuscation', desc: '29 evasion techniques' },
            { id: '03', name: 'Permission Audit', desc: 'Behavior vs declaration' },
            { id: '04', name: 'Typosquat Check', desc: 'Homoglyph + Levenshtein' },
            { id: '05', name: 'Dependency Scan', desc: '8 manifest formats' },
            { id: '06', name: 'Network Analysis', desc: 'Destination + exfil endpoints' },
            { id: '07', name: 'Exfil Detection', desc: 'Read-then-send patterns' },
            { id: '  ', name: 'All parallel', desc: 'ThreadPoolExecutor' },
          ].map(({ id, name, desc }) => (
            <div key={id} style={{
              background: 'var(--bg-surface)',
              border: '1px solid var(--border-subtle)',
              borderRadius: '8px', padding: '16px',
            }}>
              <div style={{
                fontFamily: 'var(--mono)', fontSize: '11px',
                color: 'var(--accent-blue)', marginBottom: '8px',
                fontWeight: 500,
              }}>{id}</div>
              <div style={{
                fontSize: '13px', fontWeight: 600,
                color: 'var(--text-primary)', marginBottom: '4px',
              }}>{name}</div>
              <div style={{
                fontSize: '11px', color: 'var(--text-muted)',
                fontFamily: 'var(--mono)',
              }}>{desc}</div>
            </div>
          ))}
        </div>
      </div>

      {/* Directory */}
      <div id="directory">
        <div style={{
          display: 'flex', alignItems: 'center',
          justifyContent: 'space-between', marginBottom: '12px',
        }}>
          <div style={{
            fontFamily: 'var(--mono)', fontSize: '11px',
            fontWeight: 500, color: 'var(--text-muted)',
            letterSpacing: '0.1em', textTransform: 'uppercase',
          }}>Skill Directory</div>
          <div style={{
            fontFamily: 'var(--mono)', fontSize: '11px',
            color: 'var(--text-muted)',
          }}>{skills.length} entries</div>
        </div>

        {skills.length === 0 ? (
          <div style={{
            textAlign: 'center', padding: '64px 20px',
            border: '1px dashed var(--border-subtle)',
            borderRadius: '10px',
          }}>
            <div style={{
              fontFamily: 'var(--mono)', fontSize: '13px',
              color: 'var(--text-muted)', marginBottom: '8px',
            }}>// no skills audited yet</div>
            <Link href="/submit" style={{
              color: 'var(--accent-blue)', fontSize: '13px',
              textDecoration: 'none',
            }}>Submit the first one →</Link>
          </div>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
            {skills.map((skill) => {
              const report = skill.reports?.[0]
              return (
                <Link key={skill.id} href={`/skills/${skill.id}`} style={{
                  display: 'flex', alignItems: 'center',
                  justifyContent: 'space-between',
                  padding: '16px 20px',
                  background: 'var(--bg-surface)',
                  border: '1px solid var(--border-subtle)',
                  borderRadius: '8px', textDecoration: 'none',
                }}>
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{
                      display: 'flex', alignItems: 'center',
                      gap: '10px', marginBottom: '4px', flexWrap: 'wrap',
                    }}>
                      <span style={{
                        fontFamily: 'var(--mono)',
                        fontWeight: 600, fontSize: '14px',
                        color: 'var(--text-primary)',
                      }}>{skill.name}</span>
                      {report && <RiskBadge level={report.riskLevel} passed={report.passed} />}
                    </div>
                    <div style={{
                      fontSize: '13px', color: 'var(--text-secondary)',
                      marginBottom: '2px',
                    }}>{skill.description}</div>
                    <div style={{
                      fontFamily: 'var(--mono)', fontSize: '11px',
                      color: 'var(--text-muted)',
                    }}>by {skill.author}</div>
                  </div>
                  <div style={{
                    display: 'flex', alignItems: 'center',
                    gap: '20px', flexShrink: 0, marginLeft: '20px',
                  }}>
                    {report && (
                      <div style={{ textAlign: 'right' }}>
                        <div style={{
                          fontFamily: 'var(--mono)', fontSize: '11px',
                          color: 'var(--text-muted)', marginBottom: '2px',
                          textTransform: 'uppercase', letterSpacing: '0.06em',
                        }}>score</div>
                        <div style={{
                          fontFamily: 'var(--mono)',
                          fontSize: '20px', fontWeight: 600,
                          color: report.passed ? 'var(--accent-green)' : 'var(--accent-red)',
                        }}>{report.riskScore}</div>
                      </div>
                    )}
                    <div style={{
                      fontFamily: 'var(--mono)', fontSize: '16px',
                      color: 'var(--text-muted)',
                    }}>→</div>
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