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

router.post('/', upload.single('skill'), async (req: Request, res: Response) => {
  try {
    const { name, description, author, repositoryUrl } = req.body

    if (!name || !description || !author || !repositoryUrl) {
      res.status(400).json({ error: 'name, description, author, and repositoryUrl are required' })
      return
    }

    if (!req.file) {
      res.status(400).json({ error: 'skill ZIP file is required' })
      return
    }

    const skill = await prisma.skill.create({
      data: { name, description, author, repositoryUrl },
    })

    const submission = await prisma.submission.create({
      data: { skillId: skill.id, status: 'PENDING', paymentStatus: 'UNPAID' },
    })

    processSubmission(submission.id, req.file.path).catch(async (err) => {
      console.error(`Audit failed for submission ${submission.id}:`, err)
      await prisma.submission.update({
        where: { id: submission.id },
        data: { status: 'REJECTED' },
      })
    })

    res.status(202).json({
      message: 'Submission received. Audit in progress.',
      submissionId: submission.id,
      skillId: skill.id,
    })

  } catch (err) {
    console.error(err)
    res.status(500).json({ error: 'Internal server error' })
  }
})

router.get('/:id', async (req: Request, res: Response) => {
  try {
    const submission = await prisma.submission.findUnique({
      where: { id: req.params.id },
      include: { report: { include: { findings: true } } },
    })

    if (!submission) {
      res.status(404).json({ error: 'Submission not found' })
      return
    }

    res.json(submission)
  } catch (err) {
    console.error(err)
    res.status(500).json({ error: 'Internal server error' })
  }
})

export default router