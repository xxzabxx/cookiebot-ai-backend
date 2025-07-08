# CookieBot.ai Backend - Supabase + Vercel Installation Guide

## 🚀 Quick Start (5 Minutes)

This guide will help you deploy your CookieBot.ai backend using Supabase (database) and Vercel (serverless hosting). Your credentials are already configured in this package.

### Prerequisites
- Node.js 18+ installed
- Git installed
- Vercel account (free)
- Your Supabase project is already set up

## 📋 Step 1: Local Setup

### 1.1 Extract and Navigate
```bash
# Extract the package and navigate to the directory
cd cookiebot-backend-supabase
```

### 1.2 Install Dependencies
```bash
# Create virtual environment
python -m venv venv

# Activate virtual environment
# On Windows:
venv\Scripts\activate
# On macOS/Linux:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 1.3 Test Local Connection
```bash
# Test the backend locally
python main.py
```

**Expected Output:**
```
Database tables created successfully!
 * Running on all addresses (0.0.0.0)
 * Running on http://127.0.0.1:5000
 * Running on http://[your-ip]:5000
```

### 1.4 Test API Endpoints
Open a new terminal and test:
```bash
# Health check
curl http://localhost:5000/api/health

# Expected response:
{
  "status": "healthy",
  "timestamp": "2024-01-07T...",
  "database": "connected"
}
```

## 🌐 Step 2: Deploy to Vercel

### 2.1 Install Vercel CLI
```bash
npm install -g vercel
```

### 2.2 Login to Vercel
```bash
vercel login
```

### 2.3 Deploy the Project
```bash
# In your cookiebot-backend-supabase directory
vercel

# Follow the prompts:
# ? Set up and deploy "~/cookiebot-backend-supabase"? [Y/n] y
# ? Which scope do you want to deploy to? [Your Account]
# ? Link to existing project? [y/N] n
# ? What's your project's name? cookiebot-api
# ? In which directory is your code located? ./
```

### 2.4 Set Environment Variables
```bash
# Add all required environment variables
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

### 2.5 Deploy to Production
```bash
vercel --prod
```

**Success!** Your API will be live at: `https://cookiebot-api-[random].vercel.app`

## 🔗 Step 3: Custom Domain Setup

### 3.1 Add Custom Domain
```bash
# Add your custom domain
vercel domains add api.cookiebot.ai
```

### 3.2 Configure DNS
Add this CNAME record to your DNS:
```
Type: CNAME
Name: api
Value: cname.vercel-dns.com
```

### 3.3 Verify Domain
```bash
vercel domains verify api.cookiebot.ai
```

## ✅ Step 4: Test Deployment

### 4.1 Health Check
```bash
curl https://api.cookiebot.ai/api/health
```

### 4.2 Test User Registration
```bash
curl -X POST https://api.cookiebot.ai/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "testpassword123",
    "first_name": "Test",
    "last_name": "User",
    "company": "Test Company"
  }'
```

### 4.3 Test Login
```bash
curl -X POST https://api.cookiebot.ai/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "testpassword123"
  }'
```

## 🔧 Troubleshooting

### Common Issues

#### Database Connection Error
```bash
# Check your DATABASE_URL
vercel env ls

# Update if needed
vercel env rm DATABASE_URL
vercel env add DATABASE_URL
```

#### Build Failures
```bash
# Check build logs
vercel logs

# Common fix: Update requirements.txt
pip freeze > requirements.txt
vercel --prod
```

#### CORS Issues
```bash
# Update CORS origins
vercel env add CORS_ORIGINS
# Value: https://cookiebot.ai,https://www.cookiebot.ai
```

### Environment Variables Check
```bash
# List all environment variables
vercel env ls

# Should show:
# DATABASE_URL (production)
# JWT_SECRET_KEY (production)
# SUPABASE_URL (production)
# SUPABASE_ANON_KEY (production)
# SUPABASE_SERVICE_KEY (production)
# FLASK_ENV (production)
```

## 📊 Monitoring and Maintenance

### View Logs
```bash
# Real-time logs
vercel logs --follow

# Recent logs
vercel logs
```

### Performance Monitoring
- Visit: https://vercel.com/dashboard
- Click on your project
- View analytics and performance metrics

### Database Management
- Visit: https://supabase.com/dashboard
- Click on your project
- Use the SQL editor and table editor

## 🔄 Updates and Redeployment

### Update Code
```bash
# Make changes to main.py
# Then redeploy
vercel --prod
```

### Update Environment Variables
```bash
# Update any environment variable
vercel env rm VARIABLE_NAME
vercel env add VARIABLE_NAME
vercel --prod  # Redeploy to apply changes
```

## 🎯 Next Steps

1. **Update Frontend**: Configure your frontend to use `https://api.cookiebot.ai`
2. **Test Integration**: Verify frontend-backend communication
3. **Monitor Usage**: Check Vercel and Supabase dashboards
4. **Scale**: Upgrade plans as needed

Your CookieBot.ai backend is now live and ready for production use!

