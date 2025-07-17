"""
Authentication API tests.
Tests the security fixes and authentication improvements.
"""
import pytest
from app.models.user import User


class TestUserRegistration:
    """Test user registration endpoint."""
    
    def test_successful_registration(self, client, factory):
        """Test successful user registration."""
        user_data = factory.user_data()
        response = client.post('/api/auth/register', json=user_data)
        
        assert response.status_code == 201
        data = response.get_json()
        
        assert data['success'] is True
        assert 'access_token' in data['data']
        assert 'refresh_token' in data['data']
        assert data['data']['user']['email'] == user_data['email']
    
    def test_duplicate_email_registration(self, client, factory):
        """Test registration with duplicate email."""
        user_data = factory.user_data()
        
        # First registration
        response1 = client.post('/api/auth/register', json=user_data)
        assert response1.status_code == 201
        
        # Second registration with same email
        response2 = client.post('/api/auth/register', json=user_data)
        assert response2.status_code == 409
        
        data = response2.get_json()
        assert data['success'] is False
        assert 'already exists' in data['error']['message']
    
    def test_invalid_email_registration(self, client, factory):
        """Test registration with invalid email."""
        user_data = factory.user_data()
        user_data['email'] = 'invalid-email'
        
        response = client.post('/api/auth/register', json=user_data)
        assert response.status_code == 422
        
        data = response.get_json()
        assert data['success'] is False
        assert 'validation' in data['error']['message'].lower()
    
    def test_weak_password_registration(self, client, factory):
        """Test registration with weak password."""
        user_data = factory.user_data()
        user_data['password'] = '123'  # Too weak
        
        response = client.post('/api/auth/register', json=user_data)
        assert response.status_code == 422
        
        data = response.get_json()
        assert data['success'] is False
    
    def test_missing_required_fields(self, client):
        """Test registration with missing required fields."""
        response = client.post('/api/auth/register', json={
            'email': 'test@example.com'
            # Missing password, first_name, last_name
        })
        
        assert response.status_code == 422
        data = response.get_json()
        assert data['success'] is False


class TestUserLogin:
    """Test user login endpoint."""
    
    def test_successful_login(self, client, auth, factory):
        """Test successful user login."""
        user_data = factory.user_data()
        
        # Register user first
        auth.register(user_data['email'], user_data['password'])
        
        # Login
        response = client.post('/api/auth/login', json={
            'email': user_data['email'],
            'password': user_data['password']
        })
        
        assert response.status_code == 200
        data = response.get_json()
        
        assert data['success'] is True
        assert 'access_token' in data['data']
        assert 'refresh_token' in data['data']
    
    def test_invalid_credentials(self, client, auth, factory):
        """Test login with invalid credentials."""
        user_data = factory.user_data()
        
        # Register user first
        auth.register(user_data['email'], user_data['password'])
        
        # Login with wrong password
        response = client.post('/api/auth/login', json={
            'email': user_data['email'],
            'password': 'wrong_password'
        })
        
        assert response.status_code == 401
        data = response.get_json()
        assert data['success'] is False
    
    def test_nonexistent_user_login(self, client):
        """Test login with non-existent user."""
        response = client.post('/api/auth/login', json={
            'email': 'nonexistent@example.com',
            'password': 'password123'
        })
        
        assert response.status_code == 401
        data = response.get_json()
        assert data['success'] is False
    
    def test_account_lockout(self, client, auth, factory, app):
        """Test account lockout after failed attempts."""
        user_data = factory.user_data()
        
        # Register user first
        auth.register(user_data['email'], user_data['password'])
        
        # Make 5 failed login attempts
        for _ in range(5):
            response = client.post('/api/auth/login', json={
                'email': user_data['email'],
                'password': 'wrong_password'
            })
            assert response.status_code == 401
        
        # 6th attempt should result in account lock
        response = client.post('/api/auth/login', json={
            'email': user_data['email'],
            'password': user_data['password']  # Even correct password
        })
        
        assert response.status_code == 423  # Account locked


class TestTokenRefresh:
    """Test token refresh endpoint."""
    
    def test_successful_token_refresh(self, client, auth, factory):
        """Test successful token refresh."""
        user_data = factory.user_data()
        
        # Register and login
        auth.register(user_data['email'], user_data['password'])
        login_response = client.post('/api/auth/login', json={
            'email': user_data['email'],
            'password': user_data['password']
        })
        
        refresh_token = login_response.get_json()['data']['refresh_token']
        
        # Refresh token
        response = client.post('/api/auth/refresh', headers={
            'Authorization': f'Bearer {refresh_token}'
        })
        
        assert response.status_code == 200
        data = response.get_json()
        assert 'access_token' in data['data']
    
    def test_invalid_refresh_token(self, client):
        """Test refresh with invalid token."""
        response = client.post('/api/auth/refresh', headers={
            'Authorization': 'Bearer invalid_token'
        })
        
        assert response.status_code == 401


class TestUserProfile:
    """Test user profile endpoints."""
    
    def test_get_current_user(self, client, auth_headers):
        """Test getting current user profile."""
        response = client.get('/api/auth/me', headers=auth_headers)
        
        assert response.status_code == 200
        data = response.get_json()
        assert data['success'] is True
        assert 'user' in data['data']
    
    def test_update_user_profile(self, client, auth_headers):
        """Test updating user profile."""
        update_data = {
            'first_name': 'Updated',
            'last_name': 'Name',
            'company': 'New Company'
        }
        
        response = client.put('/api/auth/me', 
                            json=update_data, 
                            headers=auth_headers)
        
        assert response.status_code == 200
        data = response.get_json()
        assert data['data']['user']['first_name'] == 'Updated'
    
    def test_unauthorized_profile_access(self, client):
        """Test accessing profile without authentication."""
        response = client.get('/api/auth/me')
        assert response.status_code == 401


class TestPasswordChange:
    """Test password change functionality."""
    
    def test_successful_password_change(self, client, auth, factory):
        """Test successful password change."""
        user_data = factory.user_data()
        
        # Register and get auth headers
        auth.register(user_data['email'], user_data['password'])
        headers = auth.get_auth_headers(user_data['email'], user_data['password'])
        
        # Change password
        response = client.post('/api/auth/change-password', json={
            'current_password': user_data['password'],
            'new_password': 'NewPassword123!'
        }, headers=headers)
        
        assert response.status_code == 200
        
        # Verify old password no longer works
        old_login = client.post('/api/auth/login', json={
            'email': user_data['email'],
            'password': user_data['password']
        })
        assert old_login.status_code == 401
        
        # Verify new password works
        new_login = client.post('/api/auth/login', json={
            'email': user_data['email'],
            'password': 'NewPassword123!'
        })
        assert new_login.status_code == 200
    
    def test_password_change_wrong_current(self, client, auth_headers):
        """Test password change with wrong current password."""
        response = client.post('/api/auth/change-password', json={
            'current_password': 'wrong_password',
            'new_password': 'NewPassword123!'
        }, headers=auth_headers)
        
        assert response.status_code == 401


class TestRateLimiting:
    """Test rate limiting on authentication endpoints."""
    
    def test_registration_rate_limit(self, client, factory):
        """Test registration rate limiting."""
        # Make multiple registration attempts
        for i in range(6):  # Limit is 5 per minute
            user_data = factory.user_data(f'test{i}@example.com')
            response = client.post('/api/auth/register', json=user_data)
            
            if i < 5:
                assert response.status_code in [201, 409]  # Success or duplicate
            else:
                assert response.status_code == 429  # Rate limited
    
    def test_login_rate_limit(self, client):
        """Test login rate limiting."""
        # Make multiple login attempts
        for i in range(11):  # Limit is 10 per minute
            response = client.post('/api/auth/login', json={
                'email': 'test@example.com',
                'password': 'password'
            })
            
            if i < 10:
                assert response.status_code in [401, 200]  # Invalid or valid
            else:
                assert response.status_code == 429  # Rate limited

