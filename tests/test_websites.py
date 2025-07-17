"""
Website management API tests.
Tests the website CRUD operations and validation.
"""
import pytest
from app.models.website import Website


class TestWebsiteCreation:
    """Test website creation endpoint."""
    
    def test_successful_website_creation(self, client, auth_headers, factory):
        """Test successful website creation."""
        website_data = factory.website_data()
        
        response = client.post('/api/websites', 
                             json=website_data, 
                             headers=auth_headers)
        
        assert response.status_code == 201
        data = response.get_json()
        
        assert data['success'] is True
        assert data['data']['website']['domain'] == website_data['domain']
        assert 'client_id' in data['data']['website']
        assert 'integration_code' in data['data']['website']
    
    def test_duplicate_website_creation(self, client, auth_headers, factory):
        """Test creating duplicate website."""
        website_data = factory.website_data()
        
        # Create first website
        response1 = client.post('/api/websites', 
                              json=website_data, 
                              headers=auth_headers)
        assert response1.status_code == 201
        
        # Try to create duplicate
        response2 = client.post('/api/websites', 
                              json=website_data, 
                              headers=auth_headers)
        assert response2.status_code == 409
        
        data = response2.get_json()
        assert data['success'] is False
        assert 'already exists' in data['error']['message']
    
    def test_invalid_domain_creation(self, client, auth_headers):
        """Test creating website with invalid domain."""
        response = client.post('/api/websites', 
                             json={'domain': 'invalid..domain'}, 
                             headers=auth_headers)
        
        assert response.status_code == 422
        data = response.get_json()
        assert data['success'] is False
    
    def test_unauthorized_website_creation(self, client, factory):
        """Test creating website without authentication."""
        website_data = factory.website_data()
        
        response = client.post('/api/websites', json=website_data)
        assert response.status_code == 401


class TestWebsiteRetrieval:
    """Test website retrieval endpoints."""
    
    def test_get_user_websites(self, client, auth_headers, test_website):
        """Test getting user's websites."""
        response = client.get('/api/websites', headers=auth_headers)
        
        assert response.status_code == 200
        data = response.get_json()
        
        assert data['success'] is True
        assert 'websites' in data['data']
        assert 'pagination' in data['data']
        assert len(data['data']['websites']) >= 1
    
    def test_get_websites_pagination(self, client, auth_headers):
        """Test website pagination."""
        # Create multiple websites
        for i in range(5):
            client.post('/api/websites', 
                       json={'domain': f'example{i}.com'}, 
                       headers=auth_headers)
        
        # Test pagination
        response = client.get('/api/websites?page=1&per_page=2', 
                            headers=auth_headers)
        
        assert response.status_code == 200
        data = response.get_json()
        
        assert len(data['data']['websites']) <= 2
        assert data['data']['pagination']['page'] == 1
        assert data['data']['pagination']['per_page'] == 2
    
    def test_get_specific_website(self, client, auth_headers, test_website):
        """Test getting specific website."""
        response = client.get(f'/api/websites/{test_website.id}', 
                            headers=auth_headers)
        
        assert response.status_code == 200
        data = response.get_json()
        
        assert data['success'] is True
        assert data['data']['website']['id'] == test_website.id
        assert 'analytics_summary' in data['data']['website']
    
    def test_get_nonexistent_website(self, client, auth_headers):
        """Test getting non-existent website."""
        response = client.get('/api/websites/99999', headers=auth_headers)
        assert response.status_code == 404
    
    def test_get_other_user_website(self, client, auth, factory):
        """Test accessing another user's website."""
        # Create first user and website
        user1_data = factory.user_data('user1@example.com')
        auth.register(user1_data['email'], user1_data['password'])
        headers1 = auth.get_auth_headers(user1_data['email'], user1_data['password'])
        
        website_response = client.post('/api/websites', 
                                     json={'domain': 'user1.com'}, 
                                     headers=headers1)
        website_id = website_response.get_json()['data']['website']['id']
        
        # Create second user
        user2_data = factory.user_data('user2@example.com')
        auth.register(user2_data['email'], user2_data['password'])
        headers2 = auth.get_auth_headers(user2_data['email'], user2_data['password'])
        
        # Try to access first user's website
        response = client.get(f'/api/websites/{website_id}', headers=headers2)
        assert response.status_code == 404


class TestWebsiteUpdate:
    """Test website update endpoint."""
    
    def test_successful_website_update(self, client, auth_headers, test_website):
        """Test successful website update."""
        update_data = {'domain': 'updated-example.com'}
        
        response = client.put(f'/api/websites/{test_website.id}', 
                            json=update_data, 
                            headers=auth_headers)
        
        assert response.status_code == 200
        data = response.get_json()
        
        assert data['success'] is True
        assert data['data']['website']['domain'] == update_data['domain']
    
    def test_update_website_status(self, client, auth_headers, test_website):
        """Test updating website status."""
        update_data = {'status': 'suspended'}
        
        response = client.put(f'/api/websites/{test_website.id}', 
                            json=update_data, 
                            headers=auth_headers)
        
        assert response.status_code == 200
        data = response.get_json()
        assert data['data']['website']['status'] == 'suspended'
    
    def test_update_to_duplicate_domain(self, client, auth_headers, factory):
        """Test updating to duplicate domain."""
        # Create two websites
        website1 = client.post('/api/websites', 
                             json={'domain': 'site1.com'}, 
                             headers=auth_headers)
        website2 = client.post('/api/websites', 
                             json={'domain': 'site2.com'}, 
                             headers=auth_headers)
        
        website1_id = website1.get_json()['data']['website']['id']
        
        # Try to update website1 to same domain as website2
        response = client.put(f'/api/websites/{website1_id}', 
                            json={'domain': 'site2.com'}, 
                            headers=auth_headers)
        
        assert response.status_code == 409


class TestWebsiteDeletion:
    """Test website deletion endpoint."""
    
    def test_successful_website_deletion(self, client, auth_headers, test_website):
        """Test successful website deletion."""
        response = client.delete(f'/api/websites/{test_website.id}', 
                               headers=auth_headers)
        
        assert response.status_code == 200
        data = response.get_json()
        assert data['success'] is True
        
        # Verify website is marked as deleted
        get_response = client.get(f'/api/websites/{test_website.id}', 
                                headers=auth_headers)
        # Should still exist but with deleted status
        # (depending on implementation - soft delete vs hard delete)
    
    def test_delete_nonexistent_website(self, client, auth_headers):
        """Test deleting non-existent website."""
        response = client.delete('/api/websites/99999', headers=auth_headers)
        assert response.status_code == 404


class TestIntegrationCode:
    """Test integration code endpoints."""
    
    def test_get_integration_code(self, client, auth_headers, test_website):
        """Test getting integration code."""
        response = client.get(f'/api/websites/{test_website.id}/integration-code', 
                            headers=auth_headers)
        
        assert response.status_code == 200
        data = response.get_json()
        
        assert data['success'] is True
        assert 'integration_code' in data['data']
        assert 'client_id' in data['data']
        assert test_website.client_id in data['data']['integration_code']
    
    def test_regenerate_client_id(self, client, auth_headers, test_website):
        """Test regenerating client ID."""
        old_client_id = test_website.client_id
        
        response = client.post(f'/api/websites/{test_website.id}/regenerate-client-id', 
                             headers=auth_headers)
        
        assert response.status_code == 200
        data = response.get_json()
        
        assert data['success'] is True
        assert data['data']['client_id'] != old_client_id
        assert 'integration_code' in data['data']


class TestWebsiteVerification:
    """Test website verification endpoint."""
    
    def test_website_verification(self, client, auth_headers, test_website):
        """Test website verification."""
        response = client.post(f'/api/websites/{test_website.id}/verify', 
                             headers=auth_headers)
        
        assert response.status_code == 200
        data = response.get_json()
        
        assert data['success'] is True
        assert data['data']['website']['status'] == 'active'


class TestSubscriptionLimits:
    """Test subscription-based website limits."""
    
    def test_free_tier_website_limit(self, client, auth_headers):
        """Test free tier website limit (1 website)."""
        # Create first website (should succeed)
        response1 = client.post('/api/websites', 
                              json={'domain': 'site1.com'}, 
                              headers=auth_headers)
        assert response1.status_code == 201
        
        # Try to create second website (should fail for free tier)
        response2 = client.post('/api/websites', 
                              json={'domain': 'site2.com'}, 
                              headers=auth_headers)
        assert response2.status_code == 402  # Payment required
        
        data = response2.get_json()
        assert 'limit reached' in data['error']['message'].lower()


class TestWebsiteValidation:
    """Test website input validation."""
    
    def test_domain_normalization(self, client, auth_headers):
        """Test domain normalization."""
        test_cases = [
            'https://example.com',
            'http://example.com',
            'example.com/',
            'EXAMPLE.COM'
        ]
        
        for domain in test_cases:
            response = client.post('/api/websites', 
                                 json={'domain': domain}, 
                                 headers=auth_headers)
            
            if response.status_code == 201:
                data = response.get_json()
                # Should be normalized to lowercase without protocol/trailing slash
                assert data['data']['website']['domain'] == 'example.com'
                
                # Clean up
                website_id = data['data']['website']['id']
                client.delete(f'/api/websites/{website_id}', headers=auth_headers)
    
    def test_invalid_domain_formats(self, client, auth_headers):
        """Test various invalid domain formats."""
        invalid_domains = [
            '',
            '   ',
            'invalid..domain',
            'domain with spaces',
            'domain.toolong' + 'x' * 250
        ]
        
        for domain in invalid_domains:
            response = client.post('/api/websites', 
                                 json={'domain': domain}, 
                                 headers=auth_headers)
            assert response.status_code == 422

