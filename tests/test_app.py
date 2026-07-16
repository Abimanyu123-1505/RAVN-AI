import pytest
from app import app
import models

@pytest.fixture
def client():
    app.config["TESTING"] = True
    # Disable CSRF for testing forms if enabled
    app.config["WTF_CSRF_ENABLED"] = False
    
    with app.test_client() as client:
        with app.app_context():
            models.init_db()
        yield client

def test_landing_page(client):
    """Test that the landing page loads successfully."""
    response = client.get("/")
    assert response.status_code == 200
    assert b"RAVN AI" in response.data

def test_login_redirect(client):
    """Test that protected routes redirect to login if not authenticated."""
    response = client.get("/dashboard")
    assert response.status_code == 302
    assert "/login" in response.headers["Location"]

def test_api_chat_requires_auth(client):
    """Test that the chat API requires authentication."""
    response = client.post("/api/chat", json={"message": "hello"})
    assert response.status_code == 302 # Redirect to login

def test_api_scan_requires_auth(client):
    """Test that the manual scan API requires authentication."""
    response = client.post("/api/scan", json={"url": "https://example.com"})
    assert response.status_code == 302 # Redirect to login
