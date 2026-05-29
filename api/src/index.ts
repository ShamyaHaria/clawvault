import express from 'express'
import cors from 'cors'
import dotenv from 'dotenv'
import rateLimit from 'express-rate-limit'
import submissionsRouter from './routes/submissions'
import skillsRouter from './routes/skills'

dotenv.config()

const app = express()
const PORT = process.env.PORT ?? 3001

app.use(cors())
app.use(express.json())

// Global rate limit — 100 requests per 15 minutes per IP
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    error: 'Too many requests. Please try again later.',
  },
})

// Submission rate limit — 5 submissions per hour per IP
const submissionLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    error: 'Submission limit reached. Maximum 5 submissions per hour per IP.',
  },
})

app.use(globalLimiter)

app.get('/health', (_req, res) => {
  res.json({ status: 'ok', service: 'clawvault-api', version: '1.0.0' })
})

app.use('/api/submissions', submissionLimiter, submissionsRouter)
app.use('/api/skills', skillsRouter)

app.use((req, res) => {
  res.status(404).json({ error: `Route ${req.method} ${req.path} not found` })
})

app.use((err: Error, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
  console.error(err.stack)
  res.status(500).json({ error: 'Internal server error' })
})

app.listen(PORT, () => {
  console.log(`ClawVault API running on http://localhost:${PORT}`)
})

export default app