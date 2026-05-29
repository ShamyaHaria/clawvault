import { Router, Request, Response } from 'express'
import prisma from '../lib/prisma'

const router = Router()

router.get('/', async (_req: Request, res: Response) => {
  try {
    const skills = await prisma.skill.findMany({
      include: {
        reports: {
          orderBy: { completedAt: 'desc' },
          take: 1,
        },
      },
      orderBy: { submittedAt: 'desc' },
    })
    res.json(skills)
  } catch (err) {
    console.error('Fetch skills error:', err)
    res.status(500).json({ error: 'Internal server error' })
  }
})

router.get('/:id', async (req: Request, res: Response) => {
  try {
    const id = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id

    if (!id.match(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i)) {
      res.status(400).json({ error: 'Invalid skill ID format' })
      return
    }

    const skill = await prisma.skill.findUnique({
      where: { id },
      include: {
        reports: {
          include: { findings: true },
          orderBy: { completedAt: 'desc' },
          take: 1,
        },
        submissions: {
          orderBy: { createdAt: 'desc' },
          take: 1,
        },
      },
    })

    if (!skill) {
      res.status(404).json({ error: 'Skill not found' })
      return
    }

    res.json(skill)
  } catch (err) {
    console.error('Fetch skill error:', err)
    res.status(500).json({ error: 'Internal server error' })
  }
})

router.get('/:id/badge', async (req: Request, res: Response) => {
  try {
    const id = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id

    const skill = await prisma.skill.findUnique({
      where: { id },
      include: {
        reports: {
          orderBy: { completedAt: 'desc' },
          take: 1,
        },
      },
    })

    if (!skill) {
      res.status(404).json({ error: 'Skill not found' })
      return
    }

    const skillWithReports = skill as any
    const passed = skillWithReports.reports[0]?.passed ?? false
    const riskLevel = skillWithReports.reports[0]?.riskLevel ?? 'unknown'

    const color = passed ? '#22c55e' : '#ef4444'
    const label = passed ? 'verified' : riskLevel

    const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="160" height="20">
  <rect width="80" height="20" fill="#0d1117"/>
  <rect x="80" width="80" height="20" fill="${color}"/>
  <text x="40" y="14" font-family="monospace" font-size="11" fill="#e2eaf4" text-anchor="middle">ClawVault</text>
  <text x="120" y="14" font-family="monospace" font-size="11" fill="#fff" text-anchor="middle">${label}</text>
</svg>`.trim()

    res.setHeader('Content-Type', 'image/svg+xml')
    res.setHeader('Cache-Control', 'no-cache')
    res.send(svg)

  } catch (err) {
    console.error('Badge error:', err)
    res.status(500).json({ error: 'Internal server error' })
  }
})

export default router