import { getSkill } from '@/lib/api'
import { CheckCircle, XCircle, ExternalLink, ArrowLeft } from 'lucide-react'
import Link from 'next/link'
import { notFound } from 'next/navigation'

function SeverityBadge({ severity }: { severity: string }) {
  const styles: Record<string, { color: string; bg: string; border: string }> = {
    critical: { color: 'var(--accent-red)', bg: 'rgba(248,81,73,0.1)', border: 'rgba(248,81,73,0.3)' },
    high:     { color: 'var(--accent-orange)', bg: 'rgba(210,153,34,0.1)', border: 'rgba(210,153,34,0.3)' },
    medium:   { color: '#e3b341', bg: 'rgba(227,179,65,0.1)', border: 'rgba(227,179,65,0.3)' },
    low:      { color: 'var(--accent-green)', bg: 'rgba(63,185,80,0.1)', border: 'rgba(63,185,80,0.3)' },
  }
  const s = styles[severity] ?? styles.low
  return (
    <span style={{
      fontSize: '10px', fontWeight: 700, letterSpacing: '0.06em',
      color: s.color, background: s.bg,
      border: `1px solid ${s.border}`,
      padding: '2px 7px', borderRadius: '20px',
      textTransform: 'uppercase',
    }}>{severity}</span>
  )
}

const DETECTOR_LABELS: Record<string, string> = {
  credential_detector:  'Credential',
  obfuscation_detector: 'Obfuscation',
  permission_scanner:   'Permission',
  typosquat_checker:    'Typosquat',
}

export default async function SkillPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params
  let skill
  try { skill = await getSkill(id) } catch { notFound() }

  const report = skill.reports?.[0]
  const findings = report?.findings ?? []
  const critical = findings.filter(f => f.severity === 'critical').length
  const high = findings.filter(f => f.severity === 'high').length

  return (
    <div style={{ maxWidth: '760px', margin: '0 auto' }}>
      <Link href="/" style={{
        display: 'inline-flex', alignItems: 'center', gap: '6px',
        fontSize: '13px', color: 'var(--text-secondary)',
        textDecoration: 'none', marginBottom: '32px',
      }}>
        <ArrowLeft size={14} /> Back to directory
      </Link>

      {/* Header card */}
      <div style={{
        background: 'var(--bg-surface)',
        border: '1px solid var(--border-subtle)',
        borderRadius: '12px', padding: '28px',
        marginBottom: '16px',
        display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: '24px',
      }}>
        <div style={{ flex: 1 }}>
          <h1 style={{
            fontFamily: 'Syne, sans-serif',
            fontSize: '24px', fontWeight: 700,
            color: 'var(--text-primary)', marginBottom: '6px',
            letterSpacing: '-0.02em',
          }}>{skill.name}</h1>
          <p style={{ fontSize: '14px', color: 'var(--text-secondary)', marginBottom: '12px', lineHeight: 1.5 }}>
            {skill.description}
          </p>
          <div style={{ display: 'flex', alignItems: 'center', gap: '16px', fontSize: '13px', color: 'var(--text-muted)' }}>
            <span>by {skill.author}</span>
            <a href={skill.repositoryUrl} target="_blank" rel="noopener noreferrer" style={{
              display: 'inline-flex', alignItems: 'center', gap: '4px',
              color: 'var(--accent-blue)', textDecoration: 'none',
            }}>
              Repository <ExternalLink size={12} />
            </a>
          </div>
        </div>

        {report && (
          <div style={{
            display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '6px',
            minWidth: '100px', textAlign: 'center',
          }}>
            {report.passed
              ? <CheckCircle size={36} color="var(--accent-green)" />
              : <XCircle size={36} color="var(--accent-red)" />
            }
            <span style={{
              fontSize: '12px', fontWeight: 600, letterSpacing: '0.04em',
              color: report.passed ? 'var(--accent-green)' : 'var(--accent-red)',
            }}>
              {report.passed ? 'VERIFIED' : `${report.riskLevel.toUpperCase()} RISK`}
            </span>
          </div>
        )}
      </div>

      {/* Stats row */}
      {report && (
        <div style={{
          display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '8px', marginBottom: '16px',
        }}>
          {[
            { label: 'Risk Score', value: report.riskScore, highlight: !report.passed },
            { label: 'Risk Level', value: report.riskLevel.toUpperCase(), highlight: false },
            { label: 'Findings', value: findings.length, highlight: findings.length > 0 },
            { label: 'Critical', value: critical, highlight: critical > 0 },
          ].map(({ label, value, highlight }) => (
            <div key={label} style={{
              background: 'var(--bg-surface)',
              border: `1px solid ${highlight ? 'rgba(248,81,73,0.25)' : 'var(--border-subtle)'}`,
              borderRadius: '10px', padding: '16px', textAlign: 'center',
            }}>
              <div style={{
                fontFamily: 'Syne, sans-serif',
                fontSize: '22px', fontWeight: 700,
                color: highlight ? 'var(--accent-red)' : 'var(--text-primary)',
              }}>{value}</div>
              <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: '4px', letterSpacing: '0.04em' }}>
                {label}
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Findings */}
      {findings.length === 0 ? (
        <div style={{
          textAlign: 'center', padding: '48px',
          border: '1px dashed var(--border-subtle)', borderRadius: '12px',
        }}>
          <CheckCircle size={28} color="var(--accent-green)" style={{ margin: '0 auto 12px' }} />
          <p style={{ color: 'var(--text-primary)', fontWeight: 500, fontSize: '14px' }}>No findings detected</p>
          <p style={{ color: 'var(--text-muted)', fontSize: '13px', marginTop: '4px' }}>This skill passed all audit layers</p>
        </div>
      ) : (
        <div>
          <div style={{
            display: 'flex', alignItems: 'center', justifyContent: 'space-between',
            marginBottom: '12px',
          }}>
            <h2 style={{
              fontFamily: 'Syne, sans-serif', fontSize: '13px', fontWeight: 600,
              color: 'var(--text-muted)', letterSpacing: '0.08em', textTransform: 'uppercase',
            }}>
              Findings
            </h2>
            <div style={{ display: 'flex', gap: '8px', fontSize: '12px' }}>
              {critical > 0 && <span style={{ color: 'var(--accent-red)' }}>{critical} critical</span>}
              {high > 0 && <span style={{ color: 'var(--accent-orange)' }}>{high} high</span>}
            </div>
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
            {findings.map((finding) => (
              <div key={finding.id} style={{
                background: 'var(--bg-surface)',
                border: '1px solid var(--border-subtle)',
                borderRadius: '10px', padding: '16px',
              }}>
                <div style={{
                  display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '8px', flexWrap: 'wrap',
                }}>
                  <SeverityBadge severity={finding.severity} />
                  <span style={{ fontSize: '11px', color: 'var(--text-muted)', fontWeight: 500 }}>
                    {DETECTOR_LABELS[finding.detector] ?? finding.detector}
                  </span>
                  <span style={{ fontSize: '11px', color: 'var(--text-muted)', fontFamily: 'monospace' }}>
                    {finding.ruleId}
                  </span>
                </div>
                <p style={{ fontSize: '13px', color: 'var(--text-primary)', marginBottom: '8px' }}>
                  {finding.description}
                </p>
                <div style={{
                  fontSize: '11px', color: 'var(--text-muted)', fontFamily: 'monospace',
                  marginBottom: finding.match ? '8px' : 0,
                }}>
                  {finding.filePath} · line {finding.lineNumber}
                </div>
                {finding.match && (
                  <div style={{
                    background: 'var(--bg-base)',
                    border: '1px solid var(--border-subtle)',
                    borderRadius: '6px', padding: '8px 12px',
                    fontSize: '12px', fontFamily: 'monospace',
                    color: 'var(--text-secondary)',
                  }}>
                    {finding.match}
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}