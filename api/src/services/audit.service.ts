import prisma from '../lib/prisma'
import { runAnalyzer, AnalyzerResult } from '../lib/analyzer'
import path from 'path'
import fs from 'fs'
import { execSync } from 'child_process'

export async function processSubmission(submissionId: string, zipPath: string) {
  const extractDir = path.resolve(zipPath + '_extracted')

  try {
    await prisma.submission.update({
      where: { id: submissionId },
      data: { status: 'AUDITING' },
    })

    fs.mkdirSync(extractDir, { recursive: true })
    execSync(`unzip -o "${zipPath}" -d "${extractDir}"`)

    const result: AnalyzerResult = await runAnalyzer(extractDir)

    const submission = await prisma.submission.findUnique({
      where: { id: submissionId },
      include: { skill: true },
    })

    if (!submission) throw new Error('Submission not found')

    const report = await prisma.auditReport.create({
      data: {
        submissionId,
        skillId: submission.skillId,
        riskScore: result.risk_score,
        riskLevel: result.risk_level,
        passed: result.passed,
        findings: {
          create: result.results.flatMap(r =>
            r.findings.map(f => ({
              detector: f.detector,
              severity: f.severity,
              ruleId: f.rule_id,
              description: f.description,
              filePath: f.file_path,
              lineNumber: f.line_number,
              match: f.match,
            }))
          ),
        },
      },
    })

    await prisma.submission.update({
      where: { id: submissionId },
      data: { status: result.passed ? 'COMPLETE' : 'REJECTED' },
    })

    return report

  } finally {
    if (fs.existsSync(extractDir)) {
      fs.rmSync(extractDir, { recursive: true, force: true })
    }
    if (fs.existsSync(zipPath)) {
      fs.unlinkSync(zipPath)
    }
  }
}