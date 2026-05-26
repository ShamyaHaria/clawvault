import { PrismaClient } from '@prisma/client'
import { PrismaPg } from '@prisma/adapter-pg'
import pg from 'pg'
import dotenv from 'dotenv'

dotenv.config()

const pool = new pg.Pool({
  connectionString: process.env.DATABASE_URL ?? 'postgresql://postgres@localhost:5432/clawvault',
})

const adapter = new PrismaPg(pool)
const prisma = new PrismaClient({ adapter })

export default prisma