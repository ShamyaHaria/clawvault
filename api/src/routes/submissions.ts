import { Router, Request, Response } from 'express'
import multer from 'multer'
import path from 'path'
import prisma from '../lib/prisma'
import { processSubmission } from '../services/audit.service'

const router = Router()

const upload = multer({
  dest: path.resolve(__dirname, '../../uploads/'),
  limits: { fileSize: 50 * 1024 * 1024 },
  fileFilter: (_req, file, cb) => {
    if (file.mimetype === 'application/zip' || file.originalname.endsWith('.zip')) {
      cb(null, true)
    } else {
      cb(new Error('Only ZIP files are accepted'))
    }
  },
})

function validateSubmissionBody(body: Record<string, unknown>): string | null {
  const { name, description, author, repositoryUrl } = body

  if (!name || typeof name !== 'string' || name.trim().length < 2) {
    return 'name must be at least 2 characters'
  }
  if (name.trim().length > 100) {
    return 'name must be under 100 characters'
  }
  if (!description || typeof description !== 'string' || description.trim().length < 10) {
    return 'description must be at least 10 characters'
  }
  if (!author || typeof author !== 'string' || author.trim().length < 2) {
    return 'author must be at least 2 characters'
  }
  if (!repositoryUrl || typeof repositoryUrl !== 'string') {
    return 'repositoryUrl is required'
  }
  try {
    const url = new URL(repositoryUrl as string)
    if (!['http:', 'https:'].includes(url.protocol)) {
      return 'repositoryUrl must be a valid http or https URL'
    }
  } catch {
    return 'repositoryUrl must be a valid URL'
  }
  return null
}

router.post('/', upload.single('skill'), async (req: Request, res: Response) => {
  try {
    const validationError = validateSubmissionBody(req.body)
    if (validationError) {
      res.status(400).json({ error: validationError })
      return
    }

    if (!req.file) {
      res.status(400).json({ error: 'skill ZIP file is required' })
      return
    }

    const { name, description, author, repositoryUrl } = req.body

    const skill = await prisma.skill.create({
      data: {
        name: name.trim(),
        description: description.trim(),
        author: author.trim(),
        repositoryUrl: repositoryUrl.trim(),
      },
    })

    const submission = await prisma.submission.create({
      data: { skillId: skill.id, status: 'PENDING', paymentStatus: 'UNPAID' },
    })

    processSubmission(submission.id, req.file.path).catch(async (err) => {
      console.error(`Audit failed for submission ${submission.id}:`, err)
      await prisma.submission.update({
        where: { id: submission.id },
        data: { status: 'REJECTED' },
      }).catch(() => {})
    })

    res.status(202).json({
      message: 'Submission received. Audit in progress.',
      submissionId: submission.id,
      skillId: skill.id,
    })

  } catch (err) {
    console.error('Submission error:', err)
    res.status(500).json({ error: 'Internal server error' })
  }
})

router.get('/:id', async (req: Request, res: Response) => {
  try {
    const id = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id

    if (!id.match(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i)) {
      res.status(400).json({ error: 'Invalid submission ID format' })
      return
    }

    const submission = await prisma.submission.findUnique({
      where: { id },
      include: { report: { include: { findings: true } } },
    })

    if (!submission) {
      res.status(404).json({ error: 'Submission not found' })
      return
    }

    res.json(submission)
  } catch (err) {
    console.error('Fetch submission error:', err)
    res.status(500).json({ error: 'Internal server error' })
  }
})

export default router