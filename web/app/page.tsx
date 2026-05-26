import Link from 'next/link'
import { Shield, CheckCircle, XCircle, AlertTriangle, ArrowRight } from 'lucide-react'
import { getSkills } from '@/lib/api'

function RiskBadge({ level, passed }: { level: string; passed: boolean }) {
  if (passed) {
    return (
      <span className="flex items-center gap-1 text-xs font-medium text-blue-400 bg-blue-950 border border-blue-800 px-2 py-0.5 rounded-full">
        <CheckCircle className="w-3 h-3" /> Verified
      </span>
    )
  }
  if (level === 'critical') {
    return (
      <span className="flex items-center gap-1 text-xs font-medium text-red-400 bg-red-950 border border-red-800 px-2 py-0.5 rounded-full">
        <XCircle className="w-3 h-3" /> Critical
      </span>
    )
  }
  if (level === 'high') {
    return (
      <span className="flex items-center gap-1 text-xs font-medium text-orange-400 bg-orange-950 border border-orange-800 px-2 py-0.5 rounded-full">
        <AlertTriangle className="w-3 h-3" /> High Risk
      </span>
    )
  }
  return (
    <span className="flex items-center gap-1 text-xs font-medium text-yellow-400 bg-yellow-950 border border-yellow-800 px-2 py-0.5 rounded-full">
      <AlertTriangle className="w-3 h-3" /> {level}
    </span>
  )
}

export default async function HomePage() {
  let skills = []
  try {
    skills = await getSkills()
  } catch {
    skills = []
  }

  return (
    <div>
      {/* Hero */}
      <div className="text-center py-16 border-b border-gray-800 mb-12">
        <div className="flex justify-center mb-4">
          <Shield className="w-12 h-12 text-blue-500" />
        </div>
        <h1 className="text-4xl font-bold text-white mb-4">
          The trusted skill registry<br />for OpenClaw
        </h1>
        <p className="text-gray-400 text-lg max-w-xl mx-auto mb-8">
          Every skill audited before it goes live. Know exactly what a skill does,
          what permissions it requests, and whether it is safe to install.
        </p>
        <div className="flex justify-center gap-4">
          <Link
            href="/submit"
            className="bg-blue-600 hover:bg-blue-500 text-white px-6 py-2.5 rounded-md font-medium transition-colors flex items-center gap-2"
          >
            Submit a Skill <ArrowRight className="w-4 h-4" />
          </Link>
          
            <a href="#directory" className="border border-gray-700 hover:border-gray-500 text-gray-300 px-6 py-2.5 rounded-md font-medium transition-colors">
              Browse Directory
            </a>
        </div>

        {/* Stats */}
        <div className="flex justify-center gap-12 mt-12 text-sm">
          <div>
            <div className="text-2xl font-bold text-white">{skills.length}</div>
            <div className="text-gray-500">Skills audited</div>
          </div>
          <div>
            <div className="text-2xl font-bold text-white">
              {skills.filter(s => s.reports?.[0]?.passed).length}
            </div>
            <div className="text-gray-500">Verified safe</div>
          </div>
          <div>
            <div className="text-2xl font-bold text-white">4</div>
            <div className="text-gray-500">Audit layers</div>
          </div>
        </div>
      </div>

      {/* Directory */}
      <div id="directory">
        <div className="flex items-center justify-between mb-6">
          <h2 className="text-xl font-semibold text-white">Skill Directory</h2>
          <span className="text-sm text-gray-500">{skills.length} skills</span>
        </div>

        {skills.length === 0 ? (
          <div className="text-center py-20 border border-dashed border-gray-800 rounded-xl">
            <Shield className="w-8 h-8 text-gray-700 mx-auto mb-3" />
            <p className="text-gray-500">No skills audited yet.</p>
            <Link href="/submit" className="text-blue-500 hover:text-blue-400 text-sm mt-2 inline-block">
              Submit the first one →
            </Link>
          </div>
        ) : (
          <div className="grid gap-4">
            {skills.map((skill) => {
              const report = skill.reports?.[0]
              return (
                <Link
                  key={skill.id}
                  href={`/skills/${skill.id}`}
                  className="flex items-center justify-between p-5 border border-gray-800 rounded-xl hover:border-gray-600 hover:bg-gray-900 transition-all group"
                >
                  <div>
                    <div className="flex items-center gap-3 mb-1">
                      <span className="font-medium text-white group-hover:text-blue-400 transition-colors">
                        {skill.name}
                      </span>
                      {report && <RiskBadge level={report.riskLevel} passed={report.passed} />}
                    </div>
                    <p className="text-sm text-gray-500">{skill.description}</p>
                    <p className="text-xs text-gray-600 mt-1">by {skill.author}</p>
                  </div>
                  <div className="text-right text-sm text-gray-600">
                    {report && (
                      <div className="text-xs">
                        Risk score: <span className="text-gray-400">{report.riskScore}</span>
                      </div>
                    )}
                    <ArrowRight className="w-4 h-4 mt-2 ml-auto text-gray-700 group-hover:text-gray-400 transition-colors" />
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