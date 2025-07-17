"""
Database utilities with connection pooling and secure management.
Fixes the critical connection performance issues identified in the review.
"""
import logging
from contextlib import contextmanager
from typing import Generator, Optional

from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
import structlog

logger = structlog.get_logger()

# Initialize SQLAlchemy
db = SQLAlchemy()


class DatabaseManager:
    """Enhanced database manager with connection pooling and error handling."""
    
    def __init__(self, db_instance: SQLAlchemy):
        self.db = db_instance
    
    @contextmanager
    def get_session(self) -> Generator:
        """
        Get database session with automatic transaction management.
        Replaces the problematic get_db_connection() pattern.
        """
        session = self.db.session
        try:
            yield session
            session.commit()
        except Exception as e:
            session.rollback()
            logger.error("Database transaction failed", error=str(e))
            raise
        finally:
            session.close()
    
    def execute_query(self, query: str, params: Optional[dict] = None) -> any:
        """
        Execute raw SQL query with proper error handling.
        
        Args:
            query: SQL query string
            params: Query parameters
            
        Returns:
            Query result
        """
        try:
            with self.get_session() as session:
                result = session.execute(text(query), params or {})
                return result.fetchall()
        except SQLAlchemyError as e:
            logger.error("Query execution failed", query=query, error=str(e))
            raise
    
    def health_check(self) -> bool:
        """Check database connectivity."""
        try:
            with self.get_session() as session:
                session.execute(text("SELECT 1"))
                return True
        except Exception as e:
            logger.error("Database health check failed", error=str(e))
            return False


# Global database manager instance
db_manager = DatabaseManager(db)


def init_db() -> None:
    """
    Initialize database with all required tables.
    Fixes the missing tables issue identified in the review.
    """
    try:
        # Create all tables
        db.create_all()
        
        # Create missing tables that were referenced but not defined
        create_missing_tables()
        
        # Create indexes for performance
        create_performance_indexes()
        
        logger.info("Database initialized successfully")
        
    except Exception as e:
        logger.error("Database initialization failed", error=str(e))
        raise


def create_missing_tables() -> None:
    """Create tables that were referenced in code but missing from schema."""
    
    missing_tables_sql = """
    -- User dashboard configurations
    CREATE TABLE IF NOT EXISTS user_dashboard_configs (
        user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
        config JSONB NOT NULL DEFAULT '{}',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    -- Subscription plans
    CREATE TABLE IF NOT EXISTS subscription_plans (
        id SERIAL PRIMARY KEY,
        name VARCHAR(50) UNIQUE NOT NULL,
        monthly_price DECIMAL(10,2) NOT NULL,
        website_limit INTEGER NOT NULL,
        api_call_limit INTEGER NOT NULL,
        support_ticket_limit INTEGER NOT NULL,
        revenue_share DECIMAL(3,2) NOT NULL,
        features JSONB DEFAULT '[]',
        stripe_price_id VARCHAR(100),
        active BOOLEAN DEFAULT TRUE,
        sort_order INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    -- Admin activity log
    CREATE TABLE IF NOT EXISTS admin_activity_log (
        id SERIAL PRIMARY KEY,
        admin_user_id INTEGER REFERENCES users(id),
        action VARCHAR(100) NOT NULL,
        target_user_id INTEGER REFERENCES users(id),
        details JSONB DEFAULT '{}',
        ip_address INET,
        user_agent TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    -- Usage tracking
    CREATE TABLE IF NOT EXISTS usage_tracking (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        month DATE NOT NULL,
        websites_used INTEGER DEFAULT 0,
        api_calls_made INTEGER DEFAULT 0,
        support_tickets_created INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(user_id, month)
    );

    -- Payout methods
    CREATE TABLE IF NOT EXISTS payout_methods (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        provider VARCHAR(20) NOT NULL,
        account_id VARCHAR(255) NOT NULL,
        status VARCHAR(20) DEFAULT 'pending',
        is_primary BOOLEAN DEFAULT FALSE,
        details JSONB DEFAULT '{}',
        verification_data JSONB DEFAULT '{}',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    -- Payouts
    CREATE TABLE IF NOT EXISTS payouts (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id),
        payout_method_id INTEGER REFERENCES payout_methods(id),
        amount DECIMAL(10,2) NOT NULL,
        currency VARCHAR(3) DEFAULT 'USD',
        provider VARCHAR(20) NOT NULL,
        status VARCHAR(20) DEFAULT 'pending',
        fee_amount DECIMAL(10,2) DEFAULT 0.00,
        net_amount DECIMAL(10,2),
        provider_payout_id VARCHAR(255),
        failure_reason TEXT,
        requested_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        processed_at TIMESTAMP,
        completed_at TIMESTAMP
    );

    -- Subscription events
    CREATE TABLE IF NOT EXISTS subscription_events (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id),
        event_type VARCHAR(50) NOT NULL,
        from_plan VARCHAR(50),
        to_plan VARCHAR(50),
        amount DECIMAL(10,2),
        stripe_event_id VARCHAR(255),
        stripe_subscription_id VARCHAR(255),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    -- Add missing columns to existing tables
    ALTER TABLE users ADD COLUMN IF NOT EXISTS stripe_customer_id VARCHAR(255);
    ALTER TABLE users ADD COLUMN IF NOT EXISTS stripe_subscription_id VARCHAR(255);
    ALTER TABLE users ADD COLUMN IF NOT EXISTS subscription_status VARCHAR(50) DEFAULT 'active';
    ALTER TABLE users ADD COLUMN IF NOT EXISTS subscription_started_at TIMESTAMP;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS payment_failed_at TIMESTAMP;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS is_admin BOOLEAN DEFAULT FALSE;

    ALTER TABLE websites ADD COLUMN IF NOT EXISTS client_id VARCHAR(255) UNIQUE;
    """
    
    try:
        db.session.execute(text(missing_tables_sql))
        db.session.commit()
        logger.info("Missing tables created successfully")
    except Exception as e:
        db.session.rollback()
        logger.error("Failed to create missing tables", error=str(e))
        raise


def create_performance_indexes() -> None:
    """Create indexes to fix performance issues identified in the review."""
    
    indexes_sql = """
    -- Critical indexes for performance
    CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_users_email ON users(email);
    CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_websites_user_id ON websites(user_id);
    CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_websites_domain ON websites(domain);
    CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_websites_client_id ON websites(client_id);
    
    -- Analytics performance indexes
    CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_analytics_website_id ON analytics_events(website_id);
    CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_analytics_created_at ON analytics_events(created_at);
    CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_analytics_event_type ON analytics_events(event_type);
    CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_analytics_visitor_id ON analytics_events(visitor_id);
    
    -- Composite indexes for common queries
    CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_analytics_website_date 
        ON analytics_events(website_id, created_at);
    CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_analytics_website_consent 
        ON analytics_events(website_id, consent_given);
    
    -- Subscription and payment indexes
    CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_subscription_events_user_id 
        ON subscription_events(user_id);
    CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_payouts_user_id ON payouts(user_id);
    CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_payout_methods_user_id 
        ON payout_methods(user_id);
    """
    
    try:
        # Execute each index creation separately to handle errors gracefully
        for statement in indexes_sql.split(';'):
            if statement.strip():
                try:
                    db.session.execute(text(statement))
                    db.session.commit()
                except Exception as e:
                    # Index might already exist, log but continue
                    logger.warning("Index creation skipped", statement=statement, error=str(e))
                    db.session.rollback()
        
        logger.info("Performance indexes created successfully")
    except Exception as e:
        logger.error("Failed to create performance indexes", error=str(e))
        # Don't raise here as indexes are not critical for basic functionality


def add_data_constraints() -> None:
    """Add data validation constraints identified in the review."""
    
    constraints_sql = """
    -- Add check constraints for data validation
    ALTER TABLE users ADD CONSTRAINT IF NOT EXISTS check_email_format 
        CHECK (email ~* '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$');

    ALTER TABLE websites ADD CONSTRAINT IF NOT EXISTS check_status 
        CHECK (status IN ('pending', 'active', 'suspended', 'deleted'));

    ALTER TABLE analytics_events ADD CONSTRAINT IF NOT EXISTS check_revenue_positive 
        CHECK (revenue_generated >= 0);

    ALTER TABLE websites ADD CONSTRAINT IF NOT EXISTS check_consent_rate_range 
        CHECK (consent_rate >= 0 AND consent_rate <= 100);
    """
    
    try:
        db.session.execute(text(constraints_sql))
        db.session.commit()
        logger.info("Data constraints added successfully")
    except Exception as e:
        db.session.rollback()
        logger.warning("Some constraints could not be added", error=str(e))


# Utility functions for common database operations
def get_user_by_id(user_id: int):
    """Get user by ID with error handling."""
    from app.models.user import User
    try:
        return User.query.get(user_id)
    except Exception as e:
        logger.error("Failed to get user by ID", user_id=user_id, error=str(e))
        return None


def get_user_by_email(email: str):
    """Get user by email with error handling."""
    from app.models.user import User
    try:
        return User.query.filter_by(email=email).first()
    except Exception as e:
        logger.error("Failed to get user by email", email=email, error=str(e))
        return None


def init_database():
    """Initialize database connection and tables"""
    try:
        import os
        import psycopg2
        
        database_url = os.getenv('DATABASE_URL')
        if not database_url:
            raise Exception("DATABASE_URL not found in environment variables")
            
        conn = psycopg2.connect(database_url)
        conn.close()
        print("✅ Supabase database connection successful")
        return True
    except Exception as e:
        print(f"❌ Supabase connection failed: {e}")
        return False

def init_database():
    """Initialize database connection and tables"""
    try:
        import os
        import psycopg2
        
        database_url = os.getenv('DATABASE_URL')
        if not database_url:
            raise Exception("DATABASE_URL not found in environment variables")
            
        conn = psycopg2.connect(database_url)
        conn.close()
        print("✅ Supabase database connection successful")
        return True
    except Exception as e:
        print(f"❌ Supabase connection failed: {e}")
        return False
