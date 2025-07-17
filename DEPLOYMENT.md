# 🚀 Deployment Guide

This guide covers deploying the refactored CookieBot.ai application to various platforms.

## 📋 Pre-Deployment Checklist

### ✅ Code Quality
- [ ] All tests pass: `pytest`
- [ ] Code coverage ≥ 80%: `pytest --cov=app`
- [ ] No security vulnerabilities: `bandit -r app/`
- [ ] Code formatting: `black app/ && isort app/`
- [ ] Type checking: `mypy app/`

### ✅ Configuration
- [ ] Environment variables configured
- [ ] Database migrations ready
- [ ] SSL certificates prepared (if needed)
- [ ] Monitoring configured
- [ ] Backup strategy in place

### ✅ Dependencies
- [ ] Requirements.txt updated
- [ ] Docker images built and tested
- [ ] External services configured (Redis, PostgreSQL)

## 🚂 Railway Deployment

Railway is the recommended platform for this application.

### Initial Setup

1. **Install Railway CLI**
   ```bash
   npm install -g @railway/cli
   railway login
   ```

2. **Create New Project**
   ```bash
   railway new
   # Select "Empty Project"
   cd your-project
   railway link
   ```

3. **Add Services**
   ```bash
   # Add PostgreSQL
   railway add postgresql
   
   # Add Redis
   railway add redis
   ```

### Environment Configuration

1. **Set Environment Variables**
   ```bash
   # Core configuration
   railway variables set FLASK_ENV=production
   railway variables set SECRET_KEY="your-super-secret-key"
   railway variables set JWT_SECRET_KEY="your-jwt-secret-key"
   
   # Database (automatically set by Railway PostgreSQL service)
   # DATABASE_URL will be automatically configured
   
   # Redis (automatically set by Railway Redis service)
   # REDIS_URL will be automatically configured
   
   # Stripe
   railway variables set STRIPE_SECRET_KEY="sk_live_..."
   railway variables set STRIPE_PUBLISHABLE_KEY="pk_live_..."
   railway variables set STRIPE_WEBHOOK_SECRET="whsec_..."
   
   # Email
   railway variables set MAIL_SERVER="smtp.gmail.com"
   railway variables set MAIL_USERNAME="your-email@gmail.com"
   railway variables set MAIL_PASSWORD="your-app-password"
   
   # CORS
   railway variables set CORS_ORIGINS="https://your-frontend.netlify.app"
   ```

2. **Deploy Application**
   ```bash
   # Deploy from current directory
   railway up
   
   # Or deploy from GitHub
   railway connect  # Connect to GitHub repo
   ```

3. **Run Database Migrations**
   ```bash
   railway run flask db upgrade
   ```

4. **Create Admin User**
   ```bash
   railway run python scripts/create_admin.py
   ```

### Custom Domain Setup

1. **Add Custom Domain**
   ```bash
   railway domain add your-api-domain.com
   ```

2. **Configure DNS**
   - Add CNAME record pointing to Railway's domain
   - Wait for SSL certificate provisioning

### Monitoring Setup

1. **Health Checks**
   ```bash
   # Railway automatically monitors /health endpoint
   curl https://your-app.railway.app/api/health
   ```

2. **Logs**
   ```bash
   railway logs
   railway logs --follow
   ```

## 🌐 Netlify Frontend Integration

Update your Netlify frontend to use the new backend.

### Frontend Configuration

1. **Update API Base URL**
   ```javascript
   // In your frontend configuration
   const API_BASE_URL = 'https://your-railway-app.railway.app/api';
   ```

2. **Environment Variables in Netlify**
   ```bash
   # In Netlify dashboard > Site settings > Environment variables
   REACT_APP_API_URL=https://your-railway-app.railway.app/api
   REACT_APP_STRIPE_PUBLISHABLE_KEY=pk_live_...
   ```

3. **Build Settings**
   ```toml
   # netlify.toml
   [build]
     command = "npm run build"
     publish = "build"
   
   [[redirects]]
     from = "/api/*"
     to = "https://your-railway-app.railway.app/api/:splat"
     status = 200
     force = true
   ```

## 🗄️ Supabase Database Setup

If using Supabase as your database:

### Database Configuration

1. **Create Supabase Project**
   - Go to https://supabase.com
   - Create new project
   - Note the database URL

2. **Configure Connection**
   ```bash
   railway variables set DATABASE_URL="postgresql://postgres:[password]@db.[project].supabase.co:5432/postgres"
   ```

3. **Run Migrations**
   ```sql
   -- In Supabase SQL editor, run migration files from migrations/ directory
   -- Or use Flask-Migrate:
   railway run flask db upgrade
   ```

4. **Set Row Level Security (RLS)**
   ```sql
   -- Enable RLS on sensitive tables
   ALTER TABLE users ENABLE ROW LEVEL SECURITY;
   ALTER TABLE websites ENABLE ROW LEVEL SECURITY;
   ALTER TABLE analytics_events ENABLE ROW LEVEL SECURITY;
   
   -- Create policies as needed
   CREATE POLICY "Users can view own data" ON users
     FOR SELECT USING (auth.uid() = id);
   ```

## 🐳 Docker Deployment

For custom Docker deployments:

### Build and Run

1. **Build Image**
   ```bash
   docker build -t cookiebot-ai .
   ```

2. **Run with Docker Compose**
   ```bash
   # For production
   docker-compose -f docker-compose.yml -f docker-compose.prod.yml up -d
   ```

3. **Environment Configuration**
   ```bash
   # Create .env file with production values
   cp .env.example .env
   # Edit .env with production values
   ```

### Production Docker Compose

```yaml
# docker-compose.prod.yml
version: '3.8'

services:
  app:
    build:
      target: production
    environment:
      - FLASK_ENV=production
    restart: unless-stopped
    
  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.prod.conf:/etc/nginx/nginx.conf
      - ./ssl:/etc/nginx/ssl
    restart: unless-stopped
```

## 🔧 Advanced Configuration

### SSL/TLS Setup

1. **Let's Encrypt with Certbot**
   ```bash
   # Install certbot
   sudo apt install certbot python3-certbot-nginx
   
   # Get certificate
   sudo certbot --nginx -d your-api-domain.com
   ```

2. **Nginx Configuration**
   ```nginx
   server {
       listen 443 ssl;
       server_name your-api-domain.com;
       
       ssl_certificate /etc/letsencrypt/live/your-api-domain.com/fullchain.pem;
       ssl_certificate_key /etc/letsencrypt/live/your-api-domain.com/privkey.pem;
       
       location / {
           proxy_pass http://app:5000;
           proxy_set_header Host $host;
           proxy_set_header X-Real-IP $remote_addr;
       }
   }
   ```

### Load Balancing

1. **Multiple App Instances**
   ```yaml
   # docker-compose.yml
   services:
     app:
       deploy:
         replicas: 3
   ```

2. **Nginx Load Balancer**
   ```nginx
   upstream app_servers {
       server app1:5000;
       server app2:5000;
       server app3:5000;
   }
   
   server {
       location / {
           proxy_pass http://app_servers;
       }
   }
   ```

### Database Optimization

1. **Connection Pooling**
   ```python
   # Already configured in app/utils/database.py
   SQLALCHEMY_ENGINE_OPTIONS = {
       'pool_size': 20,
       'pool_recycle': 3600,
       'pool_pre_ping': True
   }
   ```

2. **Read Replicas**
   ```python
   # Configure read/write splitting
   SQLALCHEMY_BINDS = {
       'read': 'postgresql://read-replica-url',
       'write': 'postgresql://primary-db-url'
   }
   ```

## 📊 Monitoring and Logging

### Application Monitoring

1. **Health Checks**
   ```bash
   # Set up monitoring service to check:
   curl https://your-app.railway.app/api/health/detailed
   ```

2. **Performance Monitoring**
   ```python
   # Add APM service (e.g., New Relic, DataDog)
   pip install newrelic
   # Configure in app/__init__.py
   ```

3. **Error Tracking**
   ```python
   # Sentry integration (already configured)
   railway variables set SENTRY_DSN="your-sentry-dsn"
   ```

### Log Management

1. **Structured Logging**
   ```bash
   # Logs are already structured in JSON format
   railway logs --json
   ```

2. **Log Aggregation**
   ```bash
   # Forward logs to external service
   # Configure in railway dashboard or use log shipping
   ```

## 🔄 CI/CD Pipeline

### GitHub Actions

```yaml
# .github/workflows/deploy.yml
name: Deploy to Railway

on:
  push:
    branches: [main]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'
      - name: Install dependencies
        run: |
          pip install -r requirements.txt
          pip install -r requirements-dev.txt
      - name: Run tests
        run: pytest --cov=app
      - name: Security check
        run: bandit -r app/

  deploy:
    needs: test
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Deploy to Railway
        run: |
          npm install -g @railway/cli
          railway login --token ${{ secrets.RAILWAY_TOKEN }}
          railway up --service ${{ secrets.RAILWAY_SERVICE_ID }}
```

## 🔐 Security Considerations

### Production Security

1. **Environment Variables**
   ```bash
   # Never commit secrets to git
   # Use Railway's environment variable management
   railway variables set SECRET_KEY="$(openssl rand -base64 32)"
   ```

2. **Database Security**
   ```sql
   -- Limit database user permissions
   CREATE USER app_user WITH PASSWORD 'secure_password';
   GRANT CONNECT ON DATABASE cookiebot_ai TO app_user;
   GRANT USAGE ON SCHEMA public TO app_user;
   GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO app_user;
   ```

3. **Network Security**
   ```bash
   # Configure firewall rules
   # Only allow necessary ports (80, 443)
   # Restrict database access to application servers only
   ```

### SSL/TLS Configuration

1. **Strong Cipher Suites**
   ```nginx
   ssl_protocols TLSv1.2 TLSv1.3;
   ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512;
   ssl_prefer_server_ciphers off;
   ```

2. **Security Headers**
   ```nginx
   add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
   add_header X-Content-Type-Options nosniff;
   add_header X-Frame-Options DENY;
   add_header X-XSS-Protection "1; mode=block";
   ```

## 🆘 Troubleshooting

### Common Issues

1. **Database Connection Issues**
   ```bash
   # Check database URL
   railway variables get DATABASE_URL
   
   # Test connection
   railway run python -c "from app import create_app; app = create_app(); print('Connected')"
   ```

2. **Memory Issues**
   ```bash
   # Monitor memory usage
   railway metrics
   
   # Optimize if needed
   railway variables set WEB_MEMORY=1024  # Increase memory limit
   ```

3. **Slow Performance**
   ```bash
   # Check database queries
   railway variables set SQLALCHEMY_ECHO=true
   
   # Monitor with APM
   railway logs --follow
   ```

### Rollback Procedure

1. **Quick Rollback**
   ```bash
   # Railway keeps deployment history
   railway rollback
   ```

2. **Database Rollback**
   ```bash
   # If database migration issues
   railway run flask db downgrade
   ```

3. **Full Recovery**
   ```bash
   # Restore from backup
   railway run python scripts/migrate_data.py migrate backup.json
   ```

## 📞 Support

### Getting Help

1. **Railway Support**: https://railway.app/help
2. **Application Logs**: `railway logs`
3. **Health Check**: `curl https://your-app.railway.app/api/health/detailed`

### Monitoring Checklist

- [ ] Health checks responding
- [ ] Database connectivity
- [ ] Redis connectivity
- [ ] SSL certificate valid
- [ ] Error rates normal
- [ ] Response times acceptable
- [ ] Memory usage stable

---

**Note**: This deployment guide ensures a production-ready, secure, and scalable deployment of your refactored CookieBot.ai application.

