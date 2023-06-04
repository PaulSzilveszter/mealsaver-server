import { config } from "dotenv"
config()

import cors from "cors"

export const CORS = cors({
    origin: '*',
    methods: '*',
    allowedHeaders: '*',
    credentials: true // Enable sending cookies and credentials
  })
export const expireTime = '15m'

export const PORT = process.env.PORT || 3000
