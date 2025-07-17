"""
Subscription and payment models for billing management.
"""
from datetime import datetime
from typing import Dict, Any, Optional

from sqlalchemy import Column, Integer, String, ForeignKey, DECIMAL, DateTime, Boolean, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import relationship
import structlog

from app.utils.database import db

logger = structlog.get_logger()


class SubscriptionPlan(db.Model):
    """Subscription plan model."""
    
    __tablename__ = 'subscription_plans'
    
    # Primary fields
    id = Column(Integer, primary_key=True)
    name = Column(String(50), unique=True, nullable=False)
    
    # Pricing
    monthly_price = Column(DECIMAL(10, 2), nullable=False)
    
    # Limits
    website_limit = Column(Integer, nullable=False)
    api_call_limit = Column(Integer, nullable=False)
    support_ticket_limit = Column(Integer, nullable=False)
    
    # Revenue sharing
    revenue_share = Column(DECIMAL(3, 2), nullable=False)  # Percentage as decimal
    
    # Features and metadata
    features = Column(JSONB, default=list)
    stripe_price_id = Column(String(100))
    active = Column(Boolean, default=True, nullable=False)
    sort_order = Column(Integer, default=0)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    
    def __repr__(self):
        return f'<SubscriptionPlan {self.name}>'
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert subscription plan to dictionary."""
        return {
            'id': self.id,
            'name': self.name,
            'monthly_price': float(self.monthly_price),
            'website_limit': self.website_limit,
            'api_call_limit': self.api_call_limit,
            'support_ticket_limit': self.support_ticket_limit,
            'revenue_share': float(self.revenue_share),
            'features': self.features or [],
            'stripe_price_id': self.stripe_price_id,
            'active': self.active,
            'sort_order': self.sort_order
        }
    
    @classmethod
    def get_plan_by_name(cls, name: str) -> Optional['SubscriptionPlan']:
        """Get subscription plan by name."""
        return cls.query.filter_by(name=name, active=True).first()
    
    @classmethod
    def get_active_plans(cls) -> list:
        """Get all active subscription plans."""
        return cls.query.filter_by(active=True).order_by(cls.sort_order).all()


class SubscriptionEvent(db.Model):
    """Subscription event model for tracking changes."""
    
    __tablename__ = 'subscription_events'
    
    # Primary fields
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    
    # Event details
    event_type = Column(String(50), nullable=False)  # created, updated, cancelled, etc.
    from_plan = Column(String(50))
    to_plan = Column(String(50))
    amount = Column(DECIMAL(10, 2))
    
    # Stripe integration
    stripe_event_id = Column(String(255))
    stripe_subscription_id = Column(String(255))
    
    # Timestamp
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    
    # Relationships
    user = relationship("User")
    
    def __repr__(self):
        return f'<SubscriptionEvent {self.event_type} for user {self.user_id}>'
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert subscription event to dictionary."""
        return {
            'id': self.id,
            'user_id': self.user_id,
            'event_type': self.event_type,
            'from_plan': self.from_plan,
            'to_plan': self.to_plan,
            'amount': float(self.amount) if self.amount else None,
            'stripe_event_id': self.stripe_event_id,
            'stripe_subscription_id': self.stripe_subscription_id,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }
    
    @classmethod
    def create_event(
        cls,
        user_id: int,
        event_type: str,
        from_plan: Optional[str] = None,
        to_plan: Optional[str] = None,
        amount: Optional[float] = None,
        stripe_event_id: Optional[str] = None,
        stripe_subscription_id: Optional[str] = None
    ) -> 'SubscriptionEvent':
        """Create new subscription event."""
        
        event = cls(
            user_id=user_id,
            event_type=event_type,
            from_plan=from_plan,
            to_plan=to_plan,
            amount=amount,
            stripe_event_id=stripe_event_id,
            stripe_subscription_id=stripe_subscription_id
        )
        
        try:
            db.session.add(event)
            db.session.commit()
            
            logger.info(
                "Subscription event created",
                event_id=event.id,
                user_id=user_id,
                event_type=event_type,
                from_plan=from_plan,
                to_plan=to_plan
            )
            
            return event
            
        except Exception as e:
            db.session.rollback()
            logger.error(
                "Failed to create subscription event",
                user_id=user_id,
                event_type=event_type,
                error=str(e)
            )
            raise


class PayoutMethod(db.Model):
    """Payout method model for user revenue withdrawals."""
    
    __tablename__ = 'payout_methods'
    
    # Primary fields
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    
    # Method details
    provider = Column(String(20), nullable=False)  # stripe, paypal
    account_id = Column(String(255), nullable=False)
    status = Column(String(20), default='pending', nullable=False)
    is_primary = Column(Boolean, default=False, nullable=False)
    
    # Additional data
    details = Column(JSONB, default=dict)
    verification_data = Column(JSONB, default=dict)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    user = relationship("User", back_populates="payout_methods")
    payouts = relationship("Payout", back_populates="payout_method")
    
    def __repr__(self):
        return f'<PayoutMethod {self.provider} for user {self.user_id}>'
    
    def to_dict(self, include_sensitive: bool = False) -> Dict[str, Any]:
        """Convert payout method to dictionary."""
        data = {
            'id': self.id,
            'provider': self.provider,
            'status': self.status,
            'is_primary': self.is_primary,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }
        
        if include_sensitive:
            data.update({
                'account_id': self.account_id,
                'details': self.details or {},
                'verification_data': self.verification_data or {}
            })
        else:
            # Mask account ID for security
            if self.account_id:
                data['account_id_masked'] = f"***{self.account_id[-4:]}"
        
        return data


class Payout(db.Model):
    """Payout model for tracking revenue withdrawals."""
    
    __tablename__ = 'payouts'
    
    # Primary fields
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    payout_method_id = Column(Integer, ForeignKey('payout_methods.id'), nullable=False)
    
    # Amount details
    amount = Column(DECIMAL(10, 2), nullable=False)
    currency = Column(String(3), default='USD', nullable=False)
    fee_amount = Column(DECIMAL(10, 2), default=0.00)
    net_amount = Column(DECIMAL(10, 2))  # Calculated field
    
    # Status and processing
    provider = Column(String(20), nullable=False)
    status = Column(String(20), default='pending', nullable=False)
    provider_payout_id = Column(String(255))
    failure_reason = Column(Text)
    
    # Timestamps
    requested_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    processed_at = Column(DateTime)
    completed_at = Column(DateTime)
    
    # Relationships
    user = relationship("User", back_populates="payouts")
    payout_method = relationship("PayoutMethod", back_populates="payouts")
    
    def __repr__(self):
        return f'<Payout {self.amount} {self.currency} for user {self.user_id}>'
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        # Calculate net amount
        if self.amount and self.fee_amount:
            self.net_amount = self.amount - self.fee_amount
        elif self.amount:
            self.net_amount = self.amount
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert payout to dictionary."""
        return {
            'id': self.id,
            'amount': float(self.amount),
            'currency': self.currency,
            'fee_amount': float(self.fee_amount or 0),
            'net_amount': float(self.net_amount or 0),
            'provider': self.provider,
            'status': self.status,
            'provider_payout_id': self.provider_payout_id,
            'failure_reason': self.failure_reason,
            'requested_at': self.requested_at.isoformat() if self.requested_at else None,
            'processed_at': self.processed_at.isoformat() if self.processed_at else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
            'payout_method': self.payout_method.to_dict() if self.payout_method else None
        }
    
    def update_status(self, new_status: str, failure_reason: Optional[str] = None) -> None:
        """Update payout status with logging."""
        old_status = self.status
        self.status = new_status
        
        if failure_reason:
            self.failure_reason = failure_reason
        
        if new_status == 'processed':
            self.processed_at = datetime.utcnow()
        elif new_status == 'completed':
            self.completed_at = datetime.utcnow()
        
        logger.info(
            "Payout status updated",
            payout_id=self.id,
            user_id=self.user_id,
            old_status=old_status,
            new_status=new_status,
            amount=float(self.amount)
        )
    
    @classmethod
    def create_payout(
        cls,
        user_id: int,
        payout_method_id: int,
        amount: float,
        provider: str
    ) -> 'Payout':
        """Create new payout request."""
        
        # Calculate fee (example: 2.9% + $0.30)
        fee_amount = (amount * 0.029) + 0.30
        
        payout = cls(
            user_id=user_id,
            payout_method_id=payout_method_id,
            amount=amount,
            fee_amount=fee_amount,
            provider=provider,
            status='pending'
        )
        
        try:
            db.session.add(payout)
            db.session.commit()
            
            logger.info(
                "Payout created",
                payout_id=payout.id,
                user_id=user_id,
                amount=amount,
                provider=provider
            )
            
            return payout
            
        except Exception as e:
            db.session.rollback()
            logger.error(
                "Failed to create payout",
                user_id=user_id,
                amount=amount,
                error=str(e)
            )
            raise

