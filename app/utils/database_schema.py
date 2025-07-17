"""
Complete database schema for CookieBot.ai application.
Includes all tables from the original 3,600+ line file.
"""

import logging
from typing import Optional

logger = logging.getLogger(__name__)


def create_all_tables(db_connection) -> bool:
    """Create all database tables if they don't exist"""
    try:
        cur = db_connection.cursor()
        
        # Core tables (already exist but ensuring they have all columns)
        cur.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                email VARCHAR(255) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                first_name VARCHAR(100),
                last_name VARCHAR(100),
                company VARCHAR(255),
                subscription_tier VARCHAR(50) DEFAULT 'free',
                subscription_status VARCHAR(50) DEFAULT 'active',
                subscription_started_at TIMESTAMP,
                payment_failed_at TIMESTAMP,
                revenue_balance DECIMAL(10,2) DEFAULT 0.00,
                stripe_customer_id VARCHAR(255),
                stripe_subscription_id VARCHAR(255),
                is_admin BOOLEAN DEFAULT FALSE,
                email_verified BOOLEAN DEFAULT FALSE,
                email_verification_token VARCHAR(255),
                password_reset_token VARCHAR(255),
                password_reset_expires TIMESTAMP,
                last_login_at TIMESTAMP,
                login_attempts INTEGER DEFAULT 0,
                locked_until TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Enhanced websites table
        cur.execute('''
            CREATE TABLE IF NOT EXISTS websites (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                domain VARCHAR(255) NOT NULL,
                client_id VARCHAR(255) UNIQUE,
                status VARCHAR(50) DEFAULT 'pending',
                visitors_today INTEGER DEFAULT 0,
                consent_rate DECIMAL(5,2) DEFAULT 0.00,
                revenue_today DECIMAL(10,2) DEFAULT 0.00,
                integration_code TEXT,
                verification_status VARCHAR(50) DEFAULT 'pending',
                verification_token VARCHAR(255),
                last_scan_at TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(user_id, domain)
            )
        ''')
        
        # Analytics events table (enhanced)
        cur.execute('''
            CREATE TABLE IF NOT EXISTS analytics_events (
                id SERIAL PRIMARY KEY,
                website_id INTEGER REFERENCES websites(id) ON DELETE CASCADE,
                event_type VARCHAR(100) NOT NULL,
                visitor_id VARCHAR(255),
                session_id VARCHAR(255),
                consent_given BOOLEAN,
                revenue_generated DECIMAL(10,2) DEFAULT 0.00,
                metadata JSONB,
                ip_address INET,
                user_agent TEXT,
                referrer TEXT,
                page_url TEXT,
                country_code VARCHAR(2),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Compliance scans table (enhanced)
        cur.execute('''
            CREATE TABLE IF NOT EXISTS compliance_scans (
                id SERIAL PRIMARY KEY,
                website_id INTEGER REFERENCES websites(id) ON DELETE CASCADE,
                scan_type VARCHAR(100) NOT NULL,
                status VARCHAR(50) DEFAULT 'pending',
                results JSONB,
                recommendations TEXT,
                compliance_score INTEGER DEFAULT 0,
                cookies_found INTEGER DEFAULT 0,
                scripts_found INTEGER DEFAULT 0,
                scan_url TEXT,
                scan_duration INTEGER,
                error_message TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                completed_at TIMESTAMP
            )
        ''')
        
        # User dashboard configurations
        cur.execute('''
            CREATE TABLE IF NOT EXISTS user_dashboard_configs (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id) ON DELETE CASCADE UNIQUE,
                config JSONB NOT NULL DEFAULT '{}',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Subscription plans
        cur.execute('''
            CREATE TABLE IF NOT EXISTS subscription_plans (
                id SERIAL PRIMARY KEY,
                name VARCHAR(100) UNIQUE NOT NULL,
                display_name VARCHAR(255) NOT NULL,
                description TEXT,
                monthly_price DECIMAL(10,2) NOT NULL,
                yearly_price DECIMAL(10,2),
                website_limit INTEGER DEFAULT 1,
                api_call_limit INTEGER DEFAULT 1000,
                support_ticket_limit INTEGER DEFAULT 1,
                revenue_share DECIMAL(3,2) DEFAULT 0.60,
                features JSONB DEFAULT '[]',
                stripe_price_id VARCHAR(255),
                stripe_yearly_price_id VARCHAR(255),
                active BOOLEAN DEFAULT TRUE,
                sort_order INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Subscription events
        cur.execute('''
            CREATE TABLE IF NOT EXISTS subscription_events (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                event_type VARCHAR(100) NOT NULL,
                from_plan VARCHAR(100),
                to_plan VARCHAR(100),
                amount DECIMAL(10,2),
                currency VARCHAR(3) DEFAULT 'USD',
                stripe_event_id VARCHAR(255),
                stripe_subscription_id VARCHAR(255),
                metadata JSONB,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Payout methods
        cur.execute('''
            CREATE TABLE IF NOT EXISTS payout_methods (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                provider VARCHAR(50) NOT NULL,
                account_id VARCHAR(255) NOT NULL,
                status VARCHAR(50) DEFAULT 'pending',
                is_primary BOOLEAN DEFAULT FALSE,
                details JSONB DEFAULT '{}',
                verification_data JSONB,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Payouts
        cur.execute('''
            CREATE TABLE IF NOT EXISTS payouts (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                payout_method_id INTEGER REFERENCES payout_methods(id),
                amount DECIMAL(10,2) NOT NULL,
                currency VARCHAR(3) DEFAULT 'USD',
                provider VARCHAR(50) NOT NULL,
                status VARCHAR(50) DEFAULT 'pending',
                fee_amount DECIMAL(10,2) DEFAULT 0.00,
                net_amount DECIMAL(10,2),
                external_id VARCHAR(255),
                failure_reason TEXT,
                requested_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                processed_at TIMESTAMP,
                completed_at TIMESTAMP
            )
        ''')
        
        # Usage tracking
        cur.execute('''
            CREATE TABLE IF NOT EXISTS usage_tracking (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                month DATE NOT NULL,
                api_calls INTEGER DEFAULT 0,
                websites_created INTEGER DEFAULT 0,
                support_tickets INTEGER DEFAULT 0,
                compliance_scans INTEGER DEFAULT 0,
                privacy_insights_clicks INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(user_id, month)
            )
        ''')
        
        # Admin activity log
        cur.execute('''
            CREATE TABLE IF NOT EXISTS admin_activity_log (
                id SERIAL PRIMARY KEY,
                admin_user_id INTEGER REFERENCES users(id),
                action VARCHAR(255) NOT NULL,
                target_user_id INTEGER REFERENCES users(id),
                details JSONB,
                ip_address INET,
                user_agent TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Contact form submissions
        cur.execute('''
            CREATE TABLE IF NOT EXISTS contact_submissions (
                id SERIAL PRIMARY KEY,
                name VARCHAR(255) NOT NULL,
                email VARCHAR(255) NOT NULL,
                company VARCHAR(255),
                subject VARCHAR(500),
                message TEXT NOT NULL,
                inquiry_type VARCHAR(100),
                status VARCHAR(50) DEFAULT 'new',
                ip_address INET,
                user_agent TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                responded_at TIMESTAMP
            )
        ''')
        
        # Privacy insights content
        cur.execute('''
            CREATE TABLE IF NOT EXISTS privacy_insights (
                id SERIAL PRIMARY KEY,
                insight_id VARCHAR(100) UNIQUE NOT NULL,
                title VARCHAR(500) NOT NULL,
                description TEXT NOT NULL,
                category VARCHAR(100) NOT NULL,
                language VARCHAR(10) DEFAULT 'en',
                cpc DECIMAL(6,4) DEFAULT 0.15,
                active BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Email templates
        cur.execute('''
            CREATE TABLE IF NOT EXISTS email_templates (
                id SERIAL PRIMARY KEY,
                template_key VARCHAR(100) UNIQUE NOT NULL,
                subject VARCHAR(500) NOT NULL,
                html_content TEXT NOT NULL,
                text_content TEXT,
                variables JSONB DEFAULT '[]',
                active BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Email queue
        cur.execute('''
            CREATE TABLE IF NOT EXISTS email_queue (
                id SERIAL PRIMARY KEY,
                to_email VARCHAR(255) NOT NULL,
                from_email VARCHAR(255) NOT NULL,
                subject VARCHAR(500) NOT NULL,
                html_content TEXT,
                text_content TEXT,
                status VARCHAR(50) DEFAULT 'pending',
                attempts INTEGER DEFAULT 0,
                max_attempts INTEGER DEFAULT 3,
                error_message TEXT,
                scheduled_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                sent_at TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Create indexes for performance
        create_indexes(cur)
        
        # Insert default data
        insert_default_data(cur)
        
        db_connection.commit()
        logger.info("All database tables created successfully")
        return True
        
    except Exception as e:
        logger.error(f"Database table creation error: {e}")
        db_connection.rollback()
        return False


def create_indexes(cur):
    """Create database indexes for performance"""
    indexes = [
        # Analytics events indexes
        "CREATE INDEX IF NOT EXISTS idx_analytics_events_website_id ON analytics_events(website_id)",
        "CREATE INDEX IF NOT EXISTS idx_analytics_events_created_at ON analytics_events(created_at)",
        "CREATE INDEX IF NOT EXISTS idx_analytics_events_event_type ON analytics_events(event_type)",
        "CREATE INDEX IF NOT EXISTS idx_analytics_events_visitor_id ON analytics_events(visitor_id)",
        
        # Websites indexes
        "CREATE INDEX IF NOT EXISTS idx_websites_user_id ON websites(user_id)",
        "CREATE INDEX IF NOT EXISTS idx_websites_client_id ON websites(client_id)",
        "CREATE INDEX IF NOT EXISTS idx_websites_domain ON websites(domain)",
        
        # Users indexes
        "CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)",
        "CREATE INDEX IF NOT EXISTS idx_users_subscription_tier ON users(subscription_tier)",
        "CREATE INDEX IF NOT EXISTS idx_users_stripe_customer_id ON users(stripe_customer_id)",
        
        # Compliance scans indexes
        "CREATE INDEX IF NOT EXISTS idx_compliance_scans_website_id ON compliance_scans(website_id)",
        "CREATE INDEX IF NOT EXISTS idx_compliance_scans_status ON compliance_scans(status)",
        "CREATE INDEX IF NOT EXISTS idx_compliance_scans_created_at ON compliance_scans(created_at)",
        
        # Subscription events indexes
        "CREATE INDEX IF NOT EXISTS idx_subscription_events_user_id ON subscription_events(user_id)",
        "CREATE INDEX IF NOT EXISTS idx_subscription_events_created_at ON subscription_events(created_at)",
        
        # Payouts indexes
        "CREATE INDEX IF NOT EXISTS idx_payouts_user_id ON payouts(user_id)",
        "CREATE INDEX IF NOT EXISTS idx_payouts_status ON payouts(status)",
        "CREATE INDEX IF NOT EXISTS idx_payouts_requested_at ON payouts(requested_at)",
        
        # Usage tracking indexes
        "CREATE INDEX IF NOT EXISTS idx_usage_tracking_user_month ON usage_tracking(user_id, month)",
        
        # Admin activity log indexes
        "CREATE INDEX IF NOT EXISTS idx_admin_activity_admin_user_id ON admin_activity_log(admin_user_id)",
        "CREATE INDEX IF NOT EXISTS idx_admin_activity_created_at ON admin_activity_log(created_at)",
        
        # Contact submissions indexes
        "CREATE INDEX IF NOT EXISTS idx_contact_submissions_created_at ON contact_submissions(created_at)",
        "CREATE INDEX IF NOT EXISTS idx_contact_submissions_status ON contact_submissions(status)",
        
        # Email queue indexes
        "CREATE INDEX IF NOT EXISTS idx_email_queue_status ON email_queue(status)",
        "CREATE INDEX IF NOT EXISTS idx_email_queue_scheduled_at ON email_queue(scheduled_at)"
    ]
    
    for index_sql in indexes:
        try:
            cur.execute(index_sql)
        except Exception as e:
            logger.warning(f"Index creation warning: {e}")


def insert_default_data(cur):
    """Insert default data into tables"""
    try:
        # Insert default subscription plans
        cur.execute("""
            INSERT INTO subscription_plans (name, display_name, description, monthly_price, yearly_price, 
                                          website_limit, api_call_limit, support_ticket_limit, revenue_share, 
                                          features, sort_order)
            VALUES 
                ('free', 'Free Plan', 'Perfect for getting started', 0.00, 0.00, 1, 1000, 1, 0.60, 
                 '["Basic analytics", "1 website", "Email support"]', 1),
                ('starter', 'Starter Plan', 'Great for small businesses', 29.00, 290.00, 5, 10000, 5, 0.65, 
                 '["Advanced analytics", "5 websites", "Priority support", "Custom branding"]', 2),
                ('professional', 'Professional Plan', 'Perfect for growing businesses', 99.00, 990.00, 25, 50000, 15, 0.70, 
                 '["Premium analytics", "25 websites", "Phone support", "API access", "White-label"]', 3),
                ('enterprise', 'Enterprise Plan', 'For large organizations', 299.00, 2990.00, 100, 200000, 50, 0.75, 
                 '["Enterprise analytics", "100 websites", "Dedicated support", "Custom integrations", "SLA"]', 4)
            ON CONFLICT (name) DO NOTHING
        """)
        
        # Insert default privacy insights
        privacy_insights = [
            ('password-security', 'Strengthen Your Password Security', 
             'Use unique passwords for each account and enable two-factor authentication to protect your personal data.', 
             'security', 'en', 0.15),
            ('privacy-settings', 'Review Your Social Media Privacy', 
             'Check your privacy settings on social platforms to control who can see your personal information.', 
             'privacy', 'en', 0.12),
            ('data-backup', 'Backup Your Important Data', 
             'Regular backups protect against data loss from cyber attacks, hardware failure, or accidental deletion.', 
             'security', 'en', 0.18),
            ('browser-privacy', 'Enhance Your Browser Privacy', 
             'Use private browsing mode and clear cookies regularly to reduce online tracking.', 
             'privacy', 'en', 0.14),
            ('wifi-security', 'Secure Your WiFi Connection', 
             'Avoid public WiFi for sensitive activities and use a VPN to encrypt your internet connection.', 
             'security', 'en', 0.20),
            ('email-protection', 'Protect Your Email Privacy', 
             'Be cautious with email attachments and links, and use encrypted email services when possible.', 
             'privacy', 'en', 0.16)
        ]
        
        for insight in privacy_insights:
            cur.execute("""
                INSERT INTO privacy_insights (insight_id, title, description, category, language, cpc)
                VALUES (%s, %s, %s, %s, %s, %s)
                ON CONFLICT (insight_id) DO NOTHING
            """, insight)
        
        # Insert default email templates
        email_templates = [
            ('welcome', 'Welcome to CookieBot.ai!', 
             '<h1>Welcome to CookieBot.ai!</h1><p>Thank you for joining us. Get started by adding your first website.</p>',
             'Welcome to CookieBot.ai! Thank you for joining us. Get started by adding your first website.'),
            ('password_reset', 'Reset Your Password', 
             '<h1>Password Reset</h1><p>Click the link below to reset your password: {{reset_link}}</p>',
             'Password Reset - Click the link to reset your password: {{reset_link}}'),
            ('payment_success', 'Payment Successful', 
             '<h1>Payment Successful</h1><p>Your subscription has been activated. Thank you for your payment!</p>',
             'Payment Successful - Your subscription has been activated. Thank you for your payment!'),
            ('payout_processed', 'Payout Processed', 
             '<h1>Payout Processed</h1><p>Your payout of ${{amount}} has been processed successfully.</p>',
             'Payout Processed - Your payout of ${{amount}} has been processed successfully.')
        ]
        
        for template in email_templates:
            cur.execute("""
                INSERT INTO email_templates (template_key, subject, html_content, text_content)
                VALUES (%s, %s, %s, %s)
                ON CONFLICT (template_key) DO NOTHING
            """, template)
        
        logger.info("Default data inserted successfully")
        
    except Exception as e:
        logger.error(f"Error inserting default data: {e}")


def add_missing_columns(db_connection) -> bool:
    """Add any missing columns to existing tables"""
    try:
        cur = db_connection.cursor()
        
        # Add missing columns to users table
        missing_user_columns = [
            "ALTER TABLE users ADD COLUMN IF NOT EXISTS stripe_customer_id VARCHAR(255)",
            "ALTER TABLE users ADD COLUMN IF NOT EXISTS stripe_subscription_id VARCHAR(255)",
            "ALTER TABLE users ADD COLUMN IF NOT EXISTS subscription_status VARCHAR(50) DEFAULT 'active'",
            "ALTER TABLE users ADD COLUMN IF NOT EXISTS subscription_started_at TIMESTAMP",
            "ALTER TABLE users ADD COLUMN IF NOT EXISTS payment_failed_at TIMESTAMP",
            "ALTER TABLE users ADD COLUMN IF NOT EXISTS is_admin BOOLEAN DEFAULT FALSE",
            "ALTER TABLE users ADD COLUMN IF NOT EXISTS email_verified BOOLEAN DEFAULT FALSE",
            "ALTER TABLE users ADD COLUMN IF NOT EXISTS email_verification_token VARCHAR(255)",
            "ALTER TABLE users ADD COLUMN IF NOT EXISTS password_reset_token VARCHAR(255)",
            "ALTER TABLE users ADD COLUMN IF NOT EXISTS password_reset_expires TIMESTAMP",
            "ALTER TABLE users ADD COLUMN IF NOT EXISTS last_login_at TIMESTAMP",
            "ALTER TABLE users ADD COLUMN IF NOT EXISTS login_attempts INTEGER DEFAULT 0",
            "ALTER TABLE users ADD COLUMN IF NOT EXISTS locked_until TIMESTAMP"
        ]
        
        # Add missing columns to websites table
        missing_website_columns = [
            "ALTER TABLE websites ADD COLUMN IF NOT EXISTS client_id VARCHAR(255)",
            "ALTER TABLE websites ADD COLUMN IF NOT EXISTS verification_status VARCHAR(50) DEFAULT 'pending'",
            "ALTER TABLE websites ADD COLUMN IF NOT EXISTS verification_token VARCHAR(255)",
            "ALTER TABLE websites ADD COLUMN IF NOT EXISTS last_scan_at TIMESTAMP"
        ]
        
        # Add missing columns to analytics_events table
        missing_analytics_columns = [
            "ALTER TABLE analytics_events ADD COLUMN IF NOT EXISTS session_id VARCHAR(255)",
            "ALTER TABLE analytics_events ADD COLUMN IF NOT EXISTS ip_address INET",
            "ALTER TABLE analytics_events ADD COLUMN IF NOT EXISTS user_agent TEXT",
            "ALTER TABLE analytics_events ADD COLUMN IF NOT EXISTS referrer TEXT",
            "ALTER TABLE analytics_events ADD COLUMN IF NOT EXISTS page_url TEXT",
            "ALTER TABLE analytics_events ADD COLUMN IF NOT EXISTS country_code VARCHAR(2)"
        ]
        
        # Add missing columns to compliance_scans table
        missing_compliance_columns = [
            "ALTER TABLE compliance_scans ADD COLUMN IF NOT EXISTS compliance_score INTEGER DEFAULT 0",
            "ALTER TABLE compliance_scans ADD COLUMN IF NOT EXISTS cookies_found INTEGER DEFAULT 0",
            "ALTER TABLE compliance_scans ADD COLUMN IF NOT EXISTS scripts_found INTEGER DEFAULT 0",
            "ALTER TABLE compliance_scans ADD COLUMN IF NOT EXISTS scan_url TEXT",
            "ALTER TABLE compliance_scans ADD COLUMN IF NOT EXISTS scan_duration INTEGER",
            "ALTER TABLE compliance_scans ADD COLUMN IF NOT EXISTS error_message TEXT",
            "ALTER TABLE compliance_scans ADD COLUMN IF NOT EXISTS completed_at TIMESTAMP"
        ]
        
        all_columns = (missing_user_columns + missing_website_columns + 
                      missing_analytics_columns + missing_compliance_columns)
        
        for column_sql in all_columns:
            try:
                cur.execute(column_sql)
            except Exception as e:
                logger.warning(f"Column addition warning: {e}")
        
        # Add unique constraint for client_id if it doesn't exist
        try:
            cur.execute("ALTER TABLE websites ADD CONSTRAINT websites_client_id_unique UNIQUE (client_id)")
        except Exception:
            pass  # Constraint might already exist
        
        db_connection.commit()
        logger.info("Missing columns added successfully")
        return True
        
    except Exception as e:
        logger.error(f"Error adding missing columns: {e}")
        db_connection.rollback()
        return False

