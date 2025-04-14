import pytest
from datetime import datetime, timedelta
from authnexus import AuthNexus, InvalidTokenError, SecurityThresholdExceeded
from authnexus.core import WebAuthnManager, SecurityConfig

@pytest.fixture
def auth_client():
    return AuthNexus(secret_key="test-secret-key-1234")

@pytest.fixture
def webauthn_client():
    return WebAuthnManager(
        config=WebAuthnConfig(rp_id="test-domain.com"),
        security_monitor=SecurityMonitor()
    )

class TestTokenAuthentication:
    def test_valid_token_flow(self, auth_client):
        """Test successful token creation and verification"""
        token = auth_client.create_token("user123")
        payload = auth_client.verify_token(token)
        assert payload["sub"] == "user123"
        assert "exp" in payload

    def test_expired_token(self, auth_client):
        """Test token expiration validation"""
        expired_token = auth_client.create_token(
            "user123",
            metadata={"exp": datetime.utcnow() - timedelta(minutes=5)}
        )
        with pytest.raises(InvalidTokenError):
            auth_client.verify_token(expired_token)

    def test_invalid_signature(self, auth_client):
        """Test token signature validation"""
        token = auth_client.create_token("user123") + "tampered"
        with pytest.raises(InvalidTokenError):
            auth_client.verify_token(token)

    def test_security_threshold(self, auth_client, mocker):
        """Test security policy enforcement"""
        mocker.patch(
            "authnexus.core.security_monitor.SecurityMonitor.check_anomalies",
            return_value=True
        )
        token = auth_client.create_token("user123")
        with pytest.raises(SecurityThresholdExceeded):
            auth_client.verify_token(token)

class TestWebAuthnFlows:
    def test_registration_flow(self, webauthn_client):
        """Test successful WebAuthn registration"""
        options = webauthn_client.generate_registration_options(
            user_id="user123",
            user_name="Test User"
        )
        assert "challenge" in options
        assert len(options["challenge"]) > 30

    def test_authentication_flow(self, webauthn_client):
        """Test complete WebAuthn authentication cycle"""
        # Registration phase
        reg_options = webauthn_client.generate_registration_options(...)
        
        # Simulate client response
        credential = {
            "id": "test-credential-id",
            "response": {
                "clientDataJSON": "..."  # Mock valid client data
            }
        }
        
        # Verification
        result = webauthn_client.verify_registration(
            credential=credential,
            expected_challenge=reg_options["challenge"]
        )
        assert "public_key" in result
        
        # Authentication phase
        auth_options = webauthn_client.generate_authentication_options()
        auth_result = webauthn_client.verify_authentication(
            credential=credential,
            expected_challenge=auth_options["challenge"],
            stored_credential=result
        )
        assert auth_result["user_id"] == "user123"

    def test_reused_challenge(self, webauthn_client):
        """Test challenge replay protection"""
        options = webauthn_client.generate_registration_options(...)
        webauthn_client.verify_registration(..., options["challenge"])
        with pytest.raises(CredentialVerificationError):
            webauthn_client.verify_registration(..., options["challenge"])
