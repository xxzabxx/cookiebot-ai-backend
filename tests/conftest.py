"""
Pytest configuration and shared fixtures.
Addresses the missing testing framework identified in the review.
"""
import pytest
import tempfile
import os
from datetime import datetime

from app import create_app
from app.utils.database import db
from app.models.user import User
from app.models.website import Website
from app.models.analytics import AnalyticsEvent


@pytest.fixture(scope='session')
def app():
    """Create application for testing."""
    # Create temporary database
    db_fd, db_path = tempfile.mkstemp()
    
    # Test configuration
    test_config = {
        'TESTING': True,
        'SQLALCHEMY_DATABASE_URI': f'sqlite:///{db_path}',
        'JWT_SECRET_KEY': 'test-secret-key-very-secure',
        'WTF_CSRF_ENABLED': False,
        'CACHE_TYPE': 'simple',
        'RATELIMIT_ENABLED': False
    }
    
    app = create_app('testing', test_config)
    
    with app.app_context():
        db.create_all()
        yield app
        db.drop_all()
    
    os.close(db_fd)
    os.unlink(db_path)


@pytest.fixture
def client(app):
    """Create test client."""
    return app.test_client()


@pytest.fixture
def runner(app):
    """Create test CLI runner."""
    return app.test_cli_runner()


@pytest.fixture
def auth_headers(client):
    """Create authentication headers for testing."""
    # Create test user
    user_data = {
        'email': 'test@example.com',
        'password': 'TestPassword123!',
        'first_name': 'Test',
        'last_name': 'User'
    }
    
    # Register user
    response = client.post('/api/auth/register', json=user_data)
    assert response.status_code == 201
    
    data = response.get_json()
    access_token = data['data']['access_token']
    
    return {'Authorization': f'Bearer {access_token}'}


@pytest.fixture
def test_user(app):
    """Create test user in database."""
    with app.app_context():
        user = User.create_user(
            email='testuser@example.com',
            password='TestPassword123!',
            first_name='Test',
            last_name='User'
        )
        db.session.commit()
        yield user
        
        # Cleanup
        db.session.delete(user)
        db.session.commit()


@pytest.fixture
def admin_user(app):
    """Create admin user in database."""
    with app.app_context():
        user = User.create_user(
            email='admin@example.com',
            password='AdminPassword123!',
            first_name='Admin',
            last_name='User'
        )
        user.is_admin = True
        db.session.commit()
        yield user
        
        # Cleanup
        db.session.delete(user)
        db.session.commit()


@pytest.fixture
def test_website(app, test_user):
    """Create test website in database."""
    with app.app_context():
        website = Website.create_website(
            user_id=test_user.id,
            domain='example.com'
        )
        db.session.commit()
        yield website
        
        # Cleanup
        db.session.delete(website)
        db.session.commit()


@pytest.fixture
def test_analytics_events(app, test_website):
    """Create test analytics events."""
    with app.app_context():
        events = []
        
        # Create various types of events
        event_types = ['page_view', 'banner_shown', 'consent_given', 'consent_denied']
        
        for i, event_type in enumerate(event_types):
            event = AnalyticsEvent.create_event(
                website_id=test_website.id,
                event_type=event_type,
                visitor_id=f'visitor_{i}',
                consent_given=event_type == 'consent_given',
                revenue_generated=1.0 if event_type == 'consent_given' else 0.0,
                metadata={'test': True}
            )
            events.append(event)
        
        db.session.commit()
        yield events
        
        # Cleanup
        for event in events:
            db.session.delete(event)
        db.session.commit()


@pytest.fixture
def mock_stripe():
    """Mock Stripe API calls."""
    import unittest.mock
    
    with unittest.mock.patch('stripe.Customer.create') as mock_customer, \
         unittest.mock.patch('stripe.Subscription.create') as mock_subscription, \
         unittest.mock.patch('stripe.PaymentMethod.attach') as mock_attach:
        
        # Configure mocks
        mock_customer.return_value = {'id': 'cus_test123'}
        mock_subscription.return_value = {
            'id': 'sub_test123',
            'status': 'active'
        }
        mock_attach.return_value = {'id': 'pm_test123'}
        
        yield {
            'customer': mock_customer,
            'subscription': mock_subscription,
            'payment_method': mock_attach
        }


class AuthActions:
    """Helper class for authentication actions in tests."""
    
    def __init__(self, client):
        self._client = client
    
    def register(self, email='test@example.com', password='TestPassword123!'):
        """Register a new user."""
        return self._client.post('/api/auth/register', json={
            'email': email,
            'password': password,
            'first_name': 'Test',
            'last_name': 'User'
        })
    
    def login(self, email='test@example.com', password='TestPassword123!'):
        """Login user and return access token."""
        response = self._client.post('/api/auth/login', json={
            'email': email,
            'password': password
        })
        
        if response.status_code == 200:
            data = response.get_json()
            return data['data']['access_token']
        return None
    
    def get_auth_headers(self, email='test@example.com', password='TestPassword123!'):
        """Get authentication headers."""
        token = self.login(email, password)
        if token:
            return {'Authorization': f'Bearer {token}'}
        return {}


@pytest.fixture
def auth(client):
    """Authentication helper."""
    return AuthActions(client)


# Test data factories
class TestDataFactory:
    """Factory for creating test data."""
    
    @staticmethod
    def user_data(email='test@example.com'):
        """Generate user data for testing."""
        return {
            'email': email,
            'password': 'TestPassword123!',
            'first_name': 'Test',
            'last_name': 'User',
            'company': 'Test Company'
        }
    
    @staticmethod
    def website_data(domain='example.com'):
        """Generate website data for testing."""
        return {
            'domain': domain
        }
    
    @staticmethod
    def analytics_event_data(client_id, event_type='page_view'):
        """Generate analytics event data for testing."""
        return {
            'client_id': client_id,
            'event_type': event_type,
            'visitor_id': 'test_visitor_123',
            'metadata': {
                'page_url': 'https://example.com/test',
                'page_title': 'Test Page'
            }
        }


@pytest.fixture
def factory():
    """Test data factory."""
    return TestDataFactory

