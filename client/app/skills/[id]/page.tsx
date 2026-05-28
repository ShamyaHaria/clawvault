import { getSkill } from '@/lib/api'
import { notFound } from 'next/navigation'
import Link from 'next/link'

function SeverityBadge({ severity }: { severity: string }) {
  const map: Record<string, { color: string; bg: string; border: string }> = {
    critical: { color: '#ef4444', bg: 'rgba(239,68,68,0.08)', border: 'rgba(239,68,68,0.2)' },
    high:     { color: '#f59e0b', bg: 'rgba(245,158,11,0.08)', border: 'rgba(245,158,11,0.2)' },
    medium:   { color: '#eab308', bg: 'rgba(234,179,8,0.08)', border: 'rgba(234,179,8,0.2)' },
    low:      { color: '#7a8fa8', bg: 'rgba(122,143,168,0.08)', border: 'rgba(122,143,168,0.2)' },
  }
  const s = map[severity] ?? map.low
  return (
    <span style={{
      fontFamily: 'var(--mono)', fontSize: '10px',
      fontWeight: 600, letterSpacing: '0.08em',
      textTransform: 'uppercase',
      color: s.color, background: s.bg,
      border: `1px solid ${s.border}`,
      padding: '2px 7px', borderRadius: '4px',
    }}>{severity}</span>
  )
}

const DETECTOR_LABELS: Record<string, string> = {
  credential_detector:          'cred',
  obfuscation_detector:         'obfs',
  permission_scanner:           'perm',
  typosquat_checker:            'typo',
  dependency_scanner:           'deps',
  network_destination_analyzer: 'net',
  exfiltration_detector:        'exfil',
}

export default async function SkillPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params
  let skill
  try { skill = await getSkill(id) } catch { notFound() }

  const report = skill.reports?.[0]
  const findings = report?.findings ?? []
  const critical = findings.filter(f => f.severity === 'critical').length
  const high = findings.filter(f => f.severity === 'high').length
  const medium = findings.filter(f => f.severity === 'medium').length

  return (
    <div style={{ maxWidth: '800px', margin: '0 auto' }}>
      {/* Back */}
      <Link href="/" style={{
        fontFamily: 'var(--mono)', fontSize: '12px',
        color: 'var(--text-muted)', textDecoration: 'none',
        display: 'inline-flex', alignItems: 'center', gap: '6px',
        marginBottom: '28px',
      }}>← directory</Link>

      {/* Header */}
      <div style={{
        background: 'var(--bg-surface)',
        border: '1px solid var(--border-subtle)',
        borderRadius: '10px', padding: '24px',
        marginBottom: '8px',
        display: 'flex', justifyContent: 'space-between',
        alignItems: 'flex-start', gap: '20px',
      }}>
        <div style={{ flex: 1 }}>
          <div style={{
            fontFamily: 'var(--mono)', fontSize: '22px',
            fontWeight: 600, color: 'var(--text-primary)',
            letterSpacing: '-0.02em', marginBottom: '8px',
          }}>{skill.name}</div>
          <div style={{
            fontSize: '14px', color: 'var(--text-secondary)',
            lineHeight: 1.6, marginBottom: '12px',
          }}>{skill.description}</div>
          <div style={{
            display: 'flex', gap: '16px', flexWrap: 'wrap',
          }}>
            <span style={{
              fontFamily: 'var(--mono)', fontSize: '12px',
              color: 'var(--text-muted)',
            }}>by {skill.author}</span>
            <a href={skill.repositoryUrl} target="_blank" rel="noopener noreferrer" style={{
              fontFamily: 'var(--mono)', fontSize: '12px',
              color: 'var(--accent-blue)', textDecoration: 'none',
            }}>repository ↗</a>
          </div>
        </div>

        {report && (
          <div style={{
            textAlign: 'center', flexShrink: 0,
            background: report.passed ? 'var(--accent-green-dim)' : 'var(--accent-red-dim)',
            border: `1px solid ${report.passed ? 'rgba(34,197,94,0.2)' : 'rgba(239,68,68,0.2)'}`,
            borderRadius: '8px', padding: '16px 20px',
            boxShadow: report.passed
              ? '0 0 20px rgba(34,197,94,0.08)'
              : '0 0 20px rgba(239,68,68,0.08)',
          }}>
            <div style={{
              fontFamily: 'var(--mono)', fontSize: '28px',
              fontWeight: 600, lineHeight: 1,
              color: report.passed ? 'var(--accent-green)' : 'var(--accent-red)',
              marginBottom: '4px',
            }}>{report.passed ? '✓' : '✗'}</div>
            <div style={{
              fontFamily: 'var(--mono)', fontSize: '10px',
              fontWeight: 600, letterSpacing: '0.1em',
              color: report.passed ? 'var(--accent-green)' : 'var(--accent-red)',
              textTransform: 'uppercase',
            }}>
              {report.passed ? 'verified' : `${report.riskLevel} risk`}
            </div>
          </div>
        )}
      </div>

      {/* Stats */}
      {report && (
        <div style={{
          display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)',
          gap: '6px', marginBottom: '8px',
        }}>
          {[
            { label: 'risk score', value: report.riskScore, alert: !report.passed },
            { label: 'risk level', value: report.riskLevel.toUpperCase(), alert: !report.passed },
            { label: 'findings', value: findings.length, alert: findings.length > 0 },
            { label: 'critical', value: critical, alert: critical > 0 },
          ].map(({ label, value, alert }) => (
            <div key={label} style={{
              background: 'var(--bg-surface)',
              border: `1px solid ${alert && Number(value) > 0 ? 'rgba(239,68,68,0.2)' : 'var(--border-subtle)'}`,
              borderRadius: '8px', padding: '14px',
              textAlign: 'center',
            }}>
              <div style={{
                fontFamily: 'var(--mono)', fontSize: '11px',
                color: 'var(--text-muted)', letterSpacing: '0.06em',
                textTransform: 'uppercase', marginBottom: '6px',
              }}>{label}</div>
              <div style={{
                fontFamily: 'var(--mono)', fontSize: '20px',
                fontWeight: 600,
                color: alert && Number(value) > 0
                  ? 'var(--accent-red)'
                  : 'var(--text-primary)',
              }}>{value}</div>
            </div>
          ))}
        </div>
      )}

      {/* Severity breakdown */}
      {findings.length > 0 && (
        <div style={{
          display: 'flex', gap: '6px', marginBottom: '20px', flexWrap: 'wrap',
        }}>
          {[
            { label: 'critical', count: critical, color: '#ef4444' },
            { label: 'high', count: high, color: '#f59e0b' },
            { label: 'medium', count: medium, color: '#eab308' },
            { label: 'low', count: findings.length - critical - high - medium, color: '#7a8fa8' },
          ].filter(s => s.count > 0).map(({ label, count, color }) => (
            <span key={label} style={{
              fontFamily: 'var(--mono)', fontSize: '11px',
              color, padding: '4px 10px',
              background: `${color}10`,
              border: `1px solid ${color}30`,
              borderRadius: '4px',
            }}>
              {count} {label}
            </span>
          ))}
        </div>
      )}

      {/* Findings */}
      {findings.length === 0 ? (
        <div style={{
          textAlign: 'center', padding: '48px',
          border: '1px dashed rgba(34,197,94,0.2)',
          borderRadius: '10px',
          background: 'rgba(34,197,94,0.02)',
        }}>
          <div style={{
            fontFamily: 'var(--mono)', fontSize: '24px',
            color: 'var(--accent-green)', marginBottom: '8px',
          }}>✓</div>
          <div style={{
            fontFamily: 'var(--mono)', fontSize: '13px',
            color: 'var(--accent-green)', marginBottom: '4px',
          }}>no findings detected</div>
          <div style={{
            fontSize: '12px', color: 'var(--text-muted)',
          }}>This skill passed all 7 audit layers</div>
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
          {findings.map((finding) => (
            <div key={finding.id} style={{
              background: 'var(--bg-surface)',
              border: '1px solid var(--border-subtle)',
              borderRadius: '8px', padding: '14px 16px',
            }}>
              <div style={{
                display: 'flex', alignItems: 'center',
                gap: '8px', marginBottom: '8px', flexWrap: 'wrap',
              }}>
                <SeverityBadge severity={finding.severity} />
                <span style={{
                  fontFamily: 'var(--mono)', fontSize: '10px',
                  color: 'var(--accent-blue)',
                  background: 'var(--accent-blue-dim)',
                  border: '1px solid rgba(59,130,246,0.2)',
                  padding: '2px 7px', borderRadius: '4px',
                }}>
                  {DETECTOR_LABELS[finding.detector] ?? finding.detector}
                </span>
                <span style={{
                  fontFamily: 'var(--mono)', fontSize: '10px',
                  color: 'var(--text-muted)',
                }}>{finding.ruleId}</span>
              </div>
              <div style={{
                fontSize: '13px', color: 'var(--text-primary)',
                marginBottom: '8px', lineHeight: 1.5,
              }}>{finding.description}</div>
              <div style={{
                fontFamily: 'var(--mono)', fontSize: '11px',
                color: 'var(--text-muted)',
                marginBottom: finding.match ? '8px' : 0,
              }}>
                {finding.filePath} · line {finding.lineNumber}
              </div>
              {finding.match && (
                <div style={{
                  background: 'var(--bg-base)',
                  border: '1px solid var(--border-subtle)',
                  borderRadius: '5px', padding: '8px 12px',
                  fontFamily: 'var(--mono)', fontSize: '12px',
                  color: 'var(--text-secondary)',
                  overflowX: 'auto',
                }}>{finding.match}</div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  )
}