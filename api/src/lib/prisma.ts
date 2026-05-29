import { PrismaClient } from '@prisma/client'
import { PrismaPg } from '@prisma/adapter-pg'
import pg from 'pg'
import dotenv from 'dotenv'

dotenv.config()

const isProduction = process.env.NODE_ENV === 'production'

const pool = new pg.Pool({
  connectionString: process.env.DATABASE_URL ?? 'postgresql://shamya@localhost:5432/clawvault',
  ssl: isProduction ? true : false,
})

const adapter = new PrismaPg(pool)
const prisma = new PrismaClient({ adapter })

export default prisma