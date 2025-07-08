# CookieBot.ai Backend - Supabase + Vercel

A production-ready Flask backend for the CookieBot.ai cookie consent management platform, optimized for Supabase database and Vercel serverless deployment.

## 🌟 Features

### 🔐 Authentication & User Management
- JWT-based authentication with secure token handling
- User registration and login with bcrypt password hashing
- Profile management with subscription tier support
- Revenue balance tracking for user payouts

### 🌐 Website Management
- Multi-website support per user account
- Domain verification and ownership validation
- Configuration management for cookie banner settings
- Real-time status monitoring and integration code generation

### 📊 Analytics & Revenue System
- Real-time visitor tracking and consent analytics
- Revenue tracking with automated 60/40 split calculation
- Dashboard metrics and performance insights
- Automated payout management with configurable minimums

### ⚖️ Compliance Management
- GDPR, CCPA, and LGPD compliance scanning
- Automated compliance scoring with actionable recommendations
- Consent record management with legal audit trails
- Privacy regulation guidance and best practices

### 🔗 Public API Endpoints
- Cookie script integration endpoints (no authentication required)
- Real-time event tracking for page views, clicks, and consents
- Consent recording with legal compliance metadata
- Analytics data collection with visitor identification

## 🚀 Quick Deployment

### Option 1: 5-Minute Quick Start
```bash
# Install Vercel CLI
npm install -g vercel

# Deploy
vercel
vercel env add DATABASE_URL  # Use provided Supabase URL
vercel env add JWT_SECRET_KEY
vercel --prod
```

### Option 2: Local Development
```bash
# Setup virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Run locally
python main.py
```

## 📡 API Endpoints

### Authentication (`/api/auth/`)
- `POST /api/auth/register` - User registration
- `POST /api/auth/login` - User login
- `GET /api/user/profile` - Get user profile (requires JWT)

### Website Management (`/api/websites/`)
- `GET /api/websites` - List user websites (requires JWT)
- `POST /api/websites` - Create new website (requires JWT)
- `PUT /api/websites/{id}` - Update website configuration (requires JWT)
- `DELETE /api/websites/{id}` - Remove website (requires JWT)

### Analytics (`/api/analytics/`)
- `GET /api/analytics/dashboard` - Dashboard overview metrics (requires JWT)
- `GET /api/analytics/website/{id}` - Website-specific analytics (requires JWT)
- `GET /api/analytics/revenue` - Revenue tracking and payouts (requires JWT)

### Public Tracking (`/api/public/`)
- `POST /api/public/track` - Track events from cookie script (no auth)
- `POST /api/public/consent` - Record consent decisions (no auth)
- `GET /api/public/config/{website_id}` - Get website configuration (no auth)

### Health & Monitoring
- `GET /api/health` - Health check and database status

## 🛠️ Configuration

### Environment Variables
```bash
# Database (Supabase PostgreSQL)
DATABASE_URL=postgresql://postgres:[password]@db.[project].supabase.co:5432/postgres

# Security
JWT_SECRET_KEY=your-secure-jwt-secret

# Supabase Integration
SUPABASE_URL=https://[project].supabase.co
SUPABASE_ANON_KEY=your-anon-key
SUPABASE_SERVICE_KEY=your-service-key

# Application
FLASK_ENV=production
CORS_ORIGINS=https://cookiebot.ai,https://www.cookiebot.ai
```

### Database Schema
The application automatically creates the following tables:
- `users` - User accounts and subscription information
- `websites` - Website configurations and domain management
- `analytics_events` - Real-time event tracking data
- `revenue_events` - Revenue tracking and payout calculations
- `compliance_scans` - Compliance scanning results and recommendations

## 🔧 Architecture

### Technology Stack
- **Framework**: Flask 2.3.3 with CORS support
- **Database**: PostgreSQL via Supabase
- **Authentication**: JWT with Flask-JWT-Extended
- **Password Security**: bcrypt hashing
- **Deployment**: Vercel serverless functions
- **Monitoring**: Built-in health checks and logging

### Scalability Features
- Serverless architecture with automatic scaling
- Connection pooling for database efficiency
- Stateless design for horizontal scaling
- Caching-ready with Redis support (optional)

### Security Features
- JWT token-based authentication
- bcrypt password hashing with salt
- CORS configuration for cross-origin requests
- SQL injection prevention with parameterized queries
- Rate limiting ready (configurable)

## 📊 Monitoring & Maintenance

### Health Monitoring
```bash
# Check API health
curl https://api.cookiebot.ai/api/health

# Expected response
{
  "status": "healthy",
  "timestamp": "2024-01-07T...",
  "database": "connected"
}
```

### Logging
- Vercel provides automatic logging and monitoring
- Access logs via `vercel logs` command
- Error tracking and performance metrics in Vercel dashboard

### Database Management
- Supabase provides visual database management
- SQL editor for custom queries and maintenance
- Automatic backups and point-in-time recovery

## 🔄 Development Workflow

### Local Development
```bash
# Activate virtual environment
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run with hot reload
FLASK_ENV=development python main.py
```

### Testing
```bash
# Test user registration
curl -X POST http://localhost:5000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"test123"}'

# Test website creation (requires JWT token)
curl -X POST http://localhost:5000/api/websites \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -d '{"domain":"example.com","name":"Test Site"}'
```

### Deployment Updates
```bash
# Update code and redeploy
git add .
git commit -m "Update backend"
vercel --prod
```

## 📈 Performance Optimization

### Database Optimization
- Indexed columns for fast queries
- Connection pooling for efficiency
- Optimized queries with proper joins

### Caching Strategy
- JWT tokens cached client-side
- Database query results cacheable with Redis
- Static configuration data cached

### Monitoring Metrics
- Response time tracking
- Database connection monitoring
- Error rate and success metrics
- User activity and engagement tracking

## 🔐 Security Best Practices

### Authentication Security
- JWT tokens with configurable expiration
- Secure password hashing with bcrypt
- Protected routes with proper authorization
- Refresh token support for extended sessions

### Data Protection
- Environment variables for sensitive data
- SQL injection prevention
- CORS configuration for trusted origins
- Input validation and sanitization

### Production Security
- HTTPS enforcement via Vercel
- Secure headers configuration
- Rate limiting capabilities
- Audit logging for compliance

## 📚 Documentation

- `INSTALLATION.md` - Complete installation and deployment guide
- `QUICK_START.md` - 5-minute deployment instructions
- `API_DOCS.md` - Detailed API endpoint documentation
- `.env.example` - Environment variable template

## 🆘 Support & Troubleshooting

### Common Issues
1. **Database Connection**: Verify DATABASE_URL and Supabase credentials
2. **CORS Errors**: Update CORS_ORIGINS with your frontend domain
3. **JWT Errors**: Ensure JWT_SECRET_KEY is set and consistent
4. **Build Failures**: Check requirements.txt and Python version

### Getting Help
- Check Vercel deployment logs: `vercel logs`
- Monitor Supabase dashboard for database issues
- Review environment variables: `vercel env ls`

## 📄 License

This project is part of the CookieBot.ai platform. All rights reserved.

---

**Ready to deploy your CookieBot.ai backend? Follow the QUICK_START.md guide for immediate deployment!**

