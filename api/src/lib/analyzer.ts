import { spawn } from 'child_process'
import path from 'path'

export interface AnalyzerResult {
  skill_path: string
  passed: boolean
  risk_score: number
  risk_level: string
  total_findings: number
  summary: Record<string, unknown>
  results: DetectorResult[]
}

export interface DetectorResult {
  detector: string
  passed: boolean
  findings: Finding[]
}

export interface Finding {
  detector: string
  severity: string
  rule_id: string
  description: string
  file_path: string
  line_number: number
  match: string
}

export function runAnalyzer(skillPath: string): Promise<AnalyzerResult> {
  return new Promise((resolve, reject) => {
    const scriptPath = path.resolve(__dirname, '../../../analyzer/run.py')

    const process = spawn('python3.11', [scriptPath, skillPath])

    let stdout = ''
    let stderr = ''

    process.stdout.on('data', (data) => { stdout += data.toString() })
    process.stderr.on('data', (data) => { stderr += data.toString() })

    process.on('close', (code) => {
      if (code !== 0) {
        reject(new Error(`Analyzer exited with code ${code}: ${stderr}`))
        return
      }
      try {
        resolve(JSON.parse(stdout))
      } catch {
        reject(new Error(`Failed to parse analyzer output: ${stdout}`))
      }
    })
  })
}