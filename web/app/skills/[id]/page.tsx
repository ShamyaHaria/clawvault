import { getSkill } from '@/lib/api'
import { Shield, CheckCircle, XCircle, AlertTriangle, ExternalLink, ArrowLeft } from 'lucide-react'
import Link from 'next/link'
import { notFound } from 'next/navigation'

function SeverityBadge({ severity }: { severity: string }) {
  const map: Record<string, string> = {
    critical: 'text-red-400 bg-red-950 border-red-800',
    high:     'text-orange-400 bg-orange-950 border-orange-800',
    medium:   'text-yellow-400 bg-yellow-950 border-yellow-800',
    low:      'text-green-400 bg-green-950 border-green-800',
  }
  return (
    <span className={`text-xs font-medium border px-2 py-0.5 rounded-full ${map[severity] ?? map.low}`}>
      {severity}
    </span>
  )
}

function DetectorLabel({ name }: { name: string }) {
  const labels: Record<string, string> = {
    credential_detector:  'Credential',
    obfuscation_detector: 'Obfuscation',
    permission_scanner:   'Permission',
    typosquat_checker:    'Typosquat',
  }
  return <span className="text-xs text-gray-500 font-mono">{labels[name] ?? name}</span>
}

export default async function SkillPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params
  let skill
  try {
    skill = await getSkill(id)
  } catch {
    notFound()
  }

  const report = skill.reports?.[0]
  const findings = report?.findings ?? []

  const bySeverity = {
    critical: findings.filter(f => f.severity === 'critical'),
    high:     findings.filter(f => f.severity === 'high'),
    medium:   findings.filter(f => f.severity === 'medium'),
    low:      findings.filter(f => f.severity === 'low'),
  }

  return (
    <div className="max-w-3xl mx-auto">
      <Link href="/" className="flex items-center gap-2 text-sm text-gray-500 hover:text-gray-300 mb-8 transition-colors">
        <ArrowLeft className="w-4 h-4" /> Back to directory
      </Link>

      {/* Header */}
      <div className="flex items-start justify-between mb-8">
        <div>
          <h1 className="text-2xl font-bold text-white mb-1">{skill.name}</h1>
          <p className="text-gray-400 mb-2">{skill.description}</p>
          <div className="flex items-center gap-4 text-sm text-gray-500">
            <span>by {skill.author}</span>
                <a href={skill.repositoryUrl} target="_blank" rel="noopener noreferrer" className="flex items-center gap-1 hover:text-blue-400 transition-colors">
                    Repository <ExternalLink className="w-3 h-3" />
                </a>
          </div>
        </div>

        {report && (
          <div className="text-center">
            {report.passed ? (
              <div className="flex flex-col items-center gap-1">
                <CheckCircle className="w-10 h-10 text-blue-500" />
                <span className="text-sm font-medium text-blue-400">Verified</span>
              </div>
            ) : (
              <div className="flex flex-col items-center gap-1">
                <XCircle className="w-10 h-10 text-red-500" />
                <span className="text-sm font-medium text-red-400 capitalize">{report.riskLevel} Risk</span>
              </div>
            )}
          </div>
        )}
      </div>

      {/* Audit summary */}
      {report && (
        <div className="grid grid-cols-4 gap-4 mb-8">
          {[
            { label: 'Risk Score', value: report.riskScore },
            { label: 'Risk Level', value: report.riskLevel },
            { label: 'Total Findings', value: findings.length },
            { label: 'Critical', value: bySeverity.critical.length },
          ].map(({ label, value }) => (
            <div key={label} className="bg-gray-900 border border-gray-800 rounded-xl p-4 text-center">
              <div className="text-xl font-bold text-white">{value}</div>
              <div className="text-xs text-gray-500 mt-1">{label}</div>
            </div>
          ))}
        </div>
      )}

      {/* Findings */}
      {findings.length === 0 ? (
        <div className="text-center py-12 border border-dashed border-gray-800 rounded-xl">
          <CheckCircle className="w-8 h-8 text-blue-500 mx-auto mb-3" />
          <p className="text-gray-400 font-medium">No findings detected</p>
          <p className="text-gray-600 text-sm mt-1">This skill passed all audit layers</p>
        </div>
      ) : (
        <div>
          <h2 className="text-lg font-semibold text-white mb-4">
            Findings <span className="text-gray-600 font-normal text-sm">({findings.length})</span>
          </h2>
          <div className="space-y-3">
            {findings.map((finding) => (
              <div key={finding.id} className="border border-gray-800 rounded-xl p-4 bg-gray-900">
                <div className="flex items-start justify-between gap-4 mb-2">
                  <div className="flex items-center gap-2 flex-wrap">
                    <SeverityBadge severity={finding.severity} />
                    <DetectorLabel name={finding.detector} />
                    <span className="text-xs font-mono text-gray-600">{finding.ruleId}</span>
                  </div>
                </div>
                <p className="text-sm text-gray-300 mb-2">{finding.description}</p>
                <div className="flex items-center gap-2 text-xs text-gray-600 font-mono">
                  <span>{finding.filePath}</span>
                  <span>·</span>
                  <span>line {finding.lineNumber}</span>
                </div>
                {finding.match && (
                  <div className="mt-2 bg-gray-950 border border-gray-800 rounded px-3 py-1.5 text-xs font-mono text-gray-400">
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