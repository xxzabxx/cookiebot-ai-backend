"""
User model with enhanced security and validation.
Fixes authentication and user management issues identified in the review.
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
    """Enhanced User model with security improvements."""
    
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
    
    # API integration
    api_key = Column(String(64), unique=True, nullable=True, index=True)
    
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
        """Generate secure API key for external integrations."""
        import secrets
        return f"cb_api_{secrets.token_urlsafe(32)}"
    
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
        
        # Feature access matrix
        feature_access = {
            'free': [
                'basic_analytics', 'single_website', 'basic_compliance'
            ],
            'basic': [
                'basic_analytics', 'multiple_websites', 'basic_compliance',
                'email_support', 'custom_banner'
            ],
            'pro': [
                'basic_analytics', 'advanced_analytics', 'unlimited_websites',
                'basic_compliance', 'advanced_compliance', 'email_support',
                'priority_support', 'custom_banner', 'white_label'
            ],
            'enterprise': [
                'basic_analytics', 'advanced_analytics', 'unlimited_websites',
                'basic_compliance', 'advanced_compliance', 'email_support',
                'priority_support', 'phone_support', 'custom_banner',
                'white_label', 'api_access', 'custom_integrations'
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
            'last_login_at': self.last_login_at.isoformat() if self.last_login_at else None
        }
        
        if include_sensitive:
            data.update({
                'stripe_customer_id': self.stripe_customer_id,
                'failed_login_attempts': self.failed_login_attempts,
                'account_locked_until': self.account_locked_until.isoformat() if self.account_locked_until else None,
                'last_login_ip': self.last_login_ip,
                'api_key': self.api_key
            })
        
        return data
    
    @classmethod
    def create_user(
        cls, 
        email: str, 
        password: str, 
        first_name: str, 
        last_name: str,
        company: Optional[str] = None
    ) -> 'User':
        """Create new user with proper validation and security."""
        # Check if user already exists
        existing_user = cls.query.filter_by(email=email.lower()).first()
        if existing_user:
            raise ValueError("User with this email already exists")
        
        # Create new user
        user = cls(
            email=email.lower().strip(),
            first_name=first_name.strip(),
            last_name=last_name.strip(),
            company=company.strip() if company else None
        )
        
        user.set_password(password)
        user.api_key = cls.generate_api_key()  # Auto-generate API key
        
        try:
            db.session.add(user)
            db.session.commit()
            
            logger.info("New user created", user_id=user.id, email=user.email)
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
            user.record_successful_login(ip_address)
            db.session.commit()
            return user
        else:
            user.record_failed_login(ip_address)
            db.session.commit()
            return None
    
    @classmethod
    def get_user_by_api_key(cls, api_key: str) -> Optional['User']:
        """Get user by API key for external integrations."""
        if not api_key or not api_key.startswith('cb_api_'):
            return None
        
        user = cls.query.filter_by(api_key=api_key).first()
        
        if user and user.is_active:
            return user
        
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

