import pytest
from app import create_app

@pytest.fixture
def client():
    app = create_app()
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

def test_home_page_loads(client):
    """Test if the home page loads correctly (GET request)"""
    response = client.get('/')
    assert response.status_code == 200
    assert b"Scam Detector Pro" in response.data

def test_post_scam_message(client):
    """Test submitting a scam message via the form (POST request)"""
    response = client.post('/', data={'message': 'urgent: update your bank password'})
    assert response.status_code == 200
    assert b"SCAM" in response.data

def test_post_safe_message(client):
    """Test submitting a safe message via the form (POST request)"""
    response = client.post('/', data={'message': 'hello, how are you doing today?'})
    assert response.status_code == 200
    assert b"NOT SCAM" in response.data