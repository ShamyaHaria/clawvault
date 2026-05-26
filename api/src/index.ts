import express from 'express'
import cors from 'cors'
import dotenv from 'dotenv'
import submissionsRouter from './routes/submissions'
import skillsRouter from './routes/skills'

dotenv.config()

const app = express()
const PORT = process.env.PORT ?? 3001

app.use(cors())
app.use(express.json())

app.get('/health', (_req, res) => {
  res.json({ status: 'ok', service: 'clawvault-api' })
})

app.use('/api/submissions', submissionsRouter)
app.use('/api/skills', skillsRouter)

app.listen(PORT, () => {
  console.log(`ClawVault API running on http://localhost:${PORT}`)
})

export default app