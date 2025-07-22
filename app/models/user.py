"""
User model with enhanced security and validation.
Enhanced with unified API key support and registration fix to solve "Validation processing failed" error.
"""
from datetime import datetime, timedelta
from typing import Optional, Dict, Any

import bcrypt
from sqlalchemy import Column, Integer, String, Boolean, DECIMAL, DateTime, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import relationship
import structlog

from app.utils.database import db

logger = structlog.get_logger()


class User(db.Model):
    """Enhanced User model with security improvements and unified API key support."""
    
    __tablename__ = 'users'
    
    # Primary fields
    id = Column(Integer, primary_key=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    
    # Profile information
    first_name = Column(String(100), nullable=False)
    last_name = Column(String(100), nullable=False)
    company = Column(String(255))
    
    # Subscription information
    subscription_tier = Column(String(50), default='free', nullable=False)
    subscription_status = Column(String(50), default='active')
    subscription_started_at = Column(DateTime)
    payment_failed_at = Column(DateTime)
    
    # Financial information
    revenue_balance = Column(DECIMAL(10, 2), default=0.00)
    
    # Stripe integration
    stripe_customer_id = Column(String(255))
    stripe_subscription_id = Column(String(255))
    
    # Admin and status
    is_admin = Column(Boolean, default=False, nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    
    # ENHANCED: API integration with unified support
    api_key = Column(String(64), unique=True, nullable=False, index=True)  # Made NOT NULL for unified approach
    
    # Security fields
    failed_login_attempts = Column(Integer, default=0)
    account_locked_until = Column(DateTime)
    last_login_at = Column(DateTime)
    last_login_ip = Column(String(45))  # IPv6 compatible
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    websites = relationship("Website", back_populates="user", cascade="all, delete-orphan")
    payout_methods = relationship("PayoutMethod", back_populates="user", cascade="all, delete-orphan")
    payouts = relationship("Payout", back_populates="user")
    
    def __repr__(self):
        return f'<User {self.email}>'
    
    @staticmethod
    def hash_password(password: str) -> str:
        """Hash password using bcrypt with secure settings."""
        # Use cost factor of 12 for good security/performance balance
        salt = bcrypt.gensalt(rounds=12)
        return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')
    
    @staticmethod
    def generate_api_key() -> str:
        """
        Generate secure API key for unified approach.
        ENHANCED: Ensures consistent format for unified API key system.
        """
        import secrets
        import string
        
        # Generate 57 random characters (64 total - 7 for prefix)
        alphabet = string.ascii_letters + string.digits + '_'
        random_part = ''.join(secrets.choice(alphabet) for _ in range(57))
        
        return f'cb_api_{random_part}'
    
    def check_password(self, password: str) -> bool:
        """Verify password against hash."""
        try:
            return bcrypt.checkpw(
                password.encode('utf-8'), 
                self.password_hash.encode('utf-8')
            )
        except Exception as e:
            logger.error("Password verification failed", user_id=self.id, error=str(e))
            return False
    
    def set_password(self, password: str) -> None:
        """Set new password with proper hashing."""
        self.password_hash = self.hash_password(password)
        self.updated_at = datetime.utcnow()
    
    def ensure_api_key(self) -> None:
        """
        REGISTRATION FIX: Ensure user has a valid API key.
        This fixes the "Validation processing failed" error during registration.
        """
        if not self.api_key or not self.api_key.startswith('cb_api_'):
            self.api_key = self.generate_api_key()
            self.updated_at = datetime.utcnow()
            
            logger.info(
                "API key generated for user",
                user_id=self.id,
                email=self.email,
                api_key_prefix=self.api_key[:10] + '...'
            )
    
    def regenerate_api_key(self) -> str:
        """
        Generate a new API key for the user.
        Useful for security purposes or if key is compromised.
        """
        old_key_prefix = self.api_key[:10] + '...' if self.api_key else 'none'
        self.api_key = self.generate_api_key()
        self.updated_at = datetime.utcnow()
        
        logger.info(
            "API key regenerated",
            user_id=self.id,
            email=self.email,
            old_key_prefix=old_key_prefix,
            new_key_prefix=self.api_key[:10] + '...'
        )
        
        return self.api_key
    
    def is_account_locked(self) -> bool:
        """Check if account is currently locked."""
        if self.account_locked_until:
            return datetime.utcnow() < self.account_locked_until
        return False
    
    def lock_account(self, duration_minutes: int = 30) -> None:
        """Lock account for specified duration."""
        self.account_locked_until = datetime.utcnow() + timedelta(minutes=duration_minutes)
        self.updated_at = datetime.utcnow()
        
        logger.warning(
            "Account locked due to failed login attempts",
            user_id=self.id,
            email=self.email,
            locked_until=self.account_locked_until
        )
    
    def unlock_account(self) -> None:
        """Unlock account and reset failed attempts."""
        self.account_locked_until = None
        self.failed_login_attempts = 0
        self.updated_at = datetime.utcnow()
        
        logger.info("Account unlocked", user_id=self.id, email=self.email)
    
    def record_failed_login(self, ip_address: str) -> None:
        """Record failed login attempt and lock if necessary."""
        self.failed_login_attempts += 1
        self.updated_at = datetime.utcnow()
        
        # Lock account after 5 failed attempts
        if self.failed_login_attempts >= 5:
            self.lock_account()
        
        logger.warning(
            "Failed login attempt recorded",
            user_id=self.id,
            email=self.email,
            attempts=self.failed_login_attempts,
            ip_address=ip_address
        )
    
    def record_successful_login(self, ip_address: str) -> None:
        """Record successful login and reset failed attempts."""
        self.failed_login_attempts = 0
        self.account_locked_until = None
        self.last_login_at = datetime.utcnow()
        self.last_login_ip = ip_address
        self.updated_at = datetime.utcnow()
        
        logger.info(
            "Successful login recorded",
            user_id=self.id,
            email=self.email,
            ip_address=ip_address
        )
    
    def can_access_feature(self, feature: str) -> bool:
        """Check if user can access a specific feature based on subscription."""
        if not self.is_active:
            return False
        
        # Enhanced feature access matrix with unified API key features
        feature_access = {
            'free': [
                'basic_analytics', 'single_website', 'basic_compliance',
                'unified_api_key'  # NEW: Unified API key available to all tiers
            ],
            'basic': [
                'basic_analytics', 'multiple_websites', 'basic_compliance',
                'email_support', 'custom_banner', 'unified_api_key',
                'cross_website_analytics'  # NEW: Cross-website analytics
            ],
            'pro': [
                'basic_analytics', 'advanced_analytics', 'unlimited_websites',
                'basic_compliance', 'advanced_compliance', 'email_support',
                'priority_support', 'custom_banner', 'white_label',
                'unified_api_key', 'cross_website_analytics', 'real_time_analytics'
            ],
            'enterprise': [
                'basic_analytics', 'advanced_analytics', 'unlimited_websites',
                'basic_compliance', 'advanced_compliance', 'email_support',
                'priority_support', 'phone_support', 'custom_banner',
                'white_label', 'api_access', 'custom_integrations',
                'unified_api_key', 'cross_website_analytics', 'real_time_analytics',
                'bulk_operations'  # NEW: Bulk operations for enterprise
            ]
        }
        
        tier_features = feature_access.get(self.subscription_tier, [])
        return feature in tier_features
    
    def get_website_limit(self) -> int:
        """Get website limit based on subscription tier."""
        limits = {
            'free': 1,
            'basic': 5,
            'pro': 25,
            'enterprise': -1  # Unlimited
        }
        return limits.get(self.subscription_tier, 1)
    
    def get_api_call_limit(self) -> int:
        """Get API call limit based on subscription tier."""
        limits = {
            'free': 1000,
            'basic': 10000,
            'pro': 100000,
            'enterprise': -1  # Unlimited
        }
        return limits.get(self.subscription_tier, 1000)
    
    def to_dict(self, include_sensitive: bool = False) -> Dict[str, Any]:
        """Convert user to dictionary for API responses."""
        data = {
            'id': self.id,
            'email': self.email,
            'first_name': self.first_name,
            'last_name': self.last_name,
            'company': self.company,
            'subscription_tier': self.subscription_tier,
            'subscription_status': self.subscription_status,
            'revenue_balance': float(self.revenue_balance) if self.revenue_balance else 0.0,
            'is_admin': self.is_admin,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'last_login_at': self.last_login_at.isoformat() if self.last_login_at else None,
            # NEW: Always include API key for unified approach
            'api_key': self.api_key,
            'unified_features_enabled': True
        }
        
        if include_sensitive:
            data.update({
                'stripe_customer_id': self.stripe_customer_id,
                'failed_login_attempts': self.failed_login_attempts,
                'account_locked_until': self.account_locked_until.isoformat() if self.account_locked_until else None,
                'last_login_ip': self.last_login_ip
            })
        
        return data
    
    @classmethod
    def create_user(
        cls, 
        email: str, 
        password: str, 
        first_name: str, 
        last_name: str,
        company: Optional[str] = None,
        api_key: Optional[str] = None  # NEW: Allow custom API key during creation
    ) -> 'User':
        """
        Create new user with proper validation and security.
        REGISTRATION FIX: Always ensures API key is generated.
        """
        # Check if user already exists
        existing_user = cls.query.filter_by(email=email.lower()).first()
        if existing_user:
            raise ValueError("User with this email already exists")
        
        # REGISTRATION FIX: Ensure API key is always provided
        if not api_key:
            api_key = cls.generate_api_key()
        
        # Validate API key format if provided
        if not api_key.startswith('cb_api_') or len(api_key) != 64:
            raise ValueError("Invalid API key format")
        
        # Check if API key already exists
        existing_api_key = cls.query.filter_by(api_key=api_key).first()
        if existing_api_key:
            # Generate a new one if collision
            api_key = cls.generate_api_key()
        
        # Create new user
        user = cls(
            email=email.lower().strip(),
            first_name=first_name.strip(),
            last_name=last_name.strip(),
            company=company.strip() if company else None,
            api_key=api_key  # REGISTRATION FIX: Always set API key
        )
        
        user.set_password(password)
        
        try:
            db.session.add(user)
            db.session.commit()
            
            logger.info(
                "New user created with unified API key",
                user_id=user.id,
                email=user.email,
                api_key_prefix=user.api_key[:10] + '...'
            )
            return user
            
        except Exception as e:
            db.session.rollback()
            logger.error("Failed to create user", email=email, error=str(e))
            raise
    
    @classmethod
    def authenticate(cls, email: str, password: str, ip_address: str) -> Optional['User']:
        """Authenticate user with enhanced security checks."""
        user = cls.query.filter_by(email=email.lower()).first()
        
        if not user:
            # Log potential enumeration attempt
            logger.warning("Login attempt for non-existent user", email=email, ip_address=ip_address)
            return None
        
        if not user.is_active:
            logger.warning("Login attempt for inactive user", user_id=user.id, ip_address=ip_address)
            return None
        
        if user.is_account_locked():
            logger.warning("Login attempt for locked account", user_id=user.id, ip_address=ip_address)
            return None
        
        if user.check_password(password):
            # REGISTRATION FIX: Ensure API key exists even for existing users
            user.ensure_api_key()
            
            user.record_successful_login(ip_address)
            db.session.commit()
            return user
        else:
            user.record_failed_login(ip_address)
            db.session.commit()
            return None
    
    @classmethod
    def get_user_by_api_key(cls, api_key: str) -> Optional['User']:
        """
        Get user by API key for unified approach.
        ENHANCED: Better validation and logging.
        """
        if not api_key or not api_key.startswith('cb_api_'):
            logger.debug("Invalid API key format", api_key_prefix=api_key[:10] + '...' if api_key else 'none')
            return None
        
        if len(api_key) != 64:
            logger.debug("Invalid API key length", api_key_length=len(api_key))
            return None
        
        user = cls.query.filter_by(api_key=api_key).first()
        
        if user and user.is_active:
            # Ensure API key is still valid format (defensive programming)
            if not user.api_key or not user.api_key.startswith('cb_api_'):
                user.ensure_api_key()
                db.session.commit()
            
            return user
        
        if user and not user.is_active:
            logger.warning("API key access attempt for inactive user", user_id=user.id)
        
        return None
    
    def update_subscription(
        self, 
        tier: str, 
        stripe_subscription_id: Optional[str] = None
    ) -> None:
        """Update user subscription with proper logging."""
        old_tier = self.subscription_tier
        
        self.subscription_tier = tier
        self.subscription_status = 'active'
        self.subscription_started_at = datetime.utcnow()
        
        if stripe_subscription_id:
            self.stripe_subscription_id = stripe_subscription_id
        
        self.updated_at = datetime.utcnow()
        
        logger.info(
            "Subscription updated",
            user_id=self.id,
            old_tier=old_tier,
            new_tier=tier,
            stripe_subscription_id=stripe_subscription_id
        )
    
    def add_revenue(self, amount: float, description: str = "") -> None:
        """Add revenue to user balance with logging."""
        old_balance = float(self.revenue_balance) if self.revenue_balance else 0.0
        self.revenue_balance = old_balance + amount
        self.updated_at = datetime.utcnow()
        
        logger.info(
            "Revenue added to user",
            user_id=self.id,
            amount=amount,
            old_balance=old_balance,
            new_balance=float(self.revenue_balance),
            description=description
        )
    
    # NEW: Unified API key management methods
    def get_unified_stats(self) -> Dict[str, Any]:
        """
        Get unified statistics across all websites for this user.
        """
        from app.models.analytics import AnalyticsEvent
        from datetime import datetime, timedelta
        
        # Get stats for last 30 days
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=30)
        
        stats = AnalyticsEvent.get_unified_analytics(
            api_key=self.api_key,
            start_date=start_date,
            end_date=end_date
        )
        
        return stats
    
    def get_website_count(self) -> int:
        """Get total number of websites for this user."""
        return len(self.websites)
    
    def can_add_website(self) -> bool:
        """Check if user can add another website based on their plan."""
        limit = self.get_website_limit()
        if limit == -1:  # Unlimited
            return True
        
        current_count = self.get_website_count()
        return current_count < limit
    
    @classmethod
    def migrate_existing_users_api_keys(cls) -> int:
        """
        MIGRATION HELPER: Ensure all existing users have API keys.
        This fixes any users created before the unified API key system.
        """
        users_without_api_keys = cls.query.filter(
            (cls.api_key.is_(None)) | 
            (~cls.api_key.startswith('cb_api_'))
        ).all()
        
        updated_count = 0
        for user in users_without_api_keys:
            user.ensure_api_key()
            updated_count += 1
        
        if updated_count > 0:
            db.session.commit()
            logger.info(f"Migrated {updated_count} users to have API keys")
        
        return updated_count

