# 🚀 CookieBot.ai Backend - 5-Minute Quick Start

## Prerequisites
- Node.js 18+ installed
- Python 3.8+ installed

## Step 1: Install Vercel CLI (1 minute)
```bash
npm install -g vercel
vercel login
```

## Step 2: Deploy (2 minutes)
```bash
# In the cookiebot-backend-supabase directory
vercel

# Follow prompts:
# Project name: cookiebot-api
# Directory: ./
```

## Step 3: Set Environment Variables (2 minutes)
```bash
# Copy and paste these commands one by one:

vercel env add DATABASE_URL
# Paste: postgresql://postgres:BlackCr0wn!!@db.rmuopxzvsyustccqytnb.supabase.co:5432/postgres

vercel env add JWT_SECRET_KEY
# Paste: cookiebot-ai-jwt-secret-2024-production-key

vercel env add SUPABASE_URL
# Paste: https://rmuopxzvsyustccqytnb.supabase.co

vercel env add SUPABASE_ANON_KEY
# Paste: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InJtdW9weHp2c3l1c3RjY3F5dG5iIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NTE5MTAwNTcsImV4cCI6MjA2NzQ4NjA1N30.QBlPGaMSgJOUFyNdqbK2vaf0zdaDXX_vu0QffnhF_C0

vercel env add SUPABASE_SERVICE_KEY
# Paste: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InJtdW9weHp2c3l1c3RjY3F5dG5iIiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTc1MTkxMDA1NywiZXhwIjoyMDY3NDg2MDU3fQ.tj-7quS6L978ZjplM6RX-fSU_P_CsZfDcPFzdi6_Bn8

vercel env add FLASK_ENV
# Type: production
```

## Step 4: Deploy to Production (30 seconds)
```bash
vercel --prod
```

## ✅ Done!
Your API is now live at: `https://cookiebot-api-[random].vercel.app`

## Test It Works
```bash
curl https://your-vercel-url.vercel.app/api/health
```

Expected response:
```json
{
  "status": "healthy",
  "timestamp": "2024-01-07T...",
  "database": "connected"
}
```

## Next: Set Up Custom Domain
```bash
vercel domains add api.cookiebot.ai
```

Then add this DNS record:
```
Type: CNAME
Name: api
Value: cname.vercel-dns.com
```

**Your CookieBot.ai backend is now live!** 🎉

