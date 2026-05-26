const API_BASE = process.env.NEXT_PUBLIC_API_URL ?? 'http://localhost:3001'

export interface Skill {
  id: string
  name: string
  description: string
  author: string
  repositoryUrl: string
  submittedAt: string
  reports: AuditReport[]
}

export interface AuditReport {
  id: string
  skillId: string
  submissionId: string
  riskScore: number
  riskLevel: string
  passed: boolean
  completedAt: string
  findings?: Finding[]
}

export interface Finding {
  id: string
  detector: string
  severity: string
  ruleId: string
  description: string
  filePath: string
  lineNumber: number
  match: string
}

export interface Submission {
  id: string
  skillId: string
  status: string
  paymentStatus: string
  createdAt: string
  report?: AuditReport
}

export async function getSkills(): Promise<Skill[]> {
  const res = await fetch(`${API_BASE}/api/skills`, { cache: 'no-store' })
  if (!res.ok) throw new Error('Failed to fetch skills')
  return res.json()
}

export async function getSkill(id: string): Promise<Skill> {
  const res = await fetch(`${API_BASE}/api/skills/${id}`, { cache: 'no-store' })
  if (!res.ok) throw new Error('Failed to fetch skill')
  return res.json()
}

export async function getSubmission(id: string): Promise<Submission> {
  const res = await fetch(`${API_BASE}/api/submissions/${id}`, { cache: 'no-store' })
  if (!res.ok) throw new Error('Failed to fetch submission')
  return res.json()
}