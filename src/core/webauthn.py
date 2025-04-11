import os
import logging
from typing import Optional, Dict, Any
from webauthn import (
    generate_registration_options,
    verify_registration_response,
    generate_authentication_options,
    verify_authentication_response,
    options_to_json,
)
from webauthn.helpers import (
    bytes_to_base64url,
    base64url_to_bytes,
    parse_authentication_credential_json,
    parse_registration_credential_json,
)
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    UserVerificationRequirement,
    RegistrationCredential,
    AuthenticationCredential,
)
from pydantic import BaseModel
from ..exceptions import CredentialVerificationError
from .security_monitor import SecurityMonitor

logger = logging.getLogger(__name__)

class WebAuthnConfig(BaseModel):
    rp_id: str = os.getenv("DOMAIN", "localhost")
    rp_name: str = "AuthNexus"
    challenge_timeout: int = 300
    user_verification: UserVerificationRequirement = "preferred"

class WebAuthnManager:
    def __init__(self, config: WebAuthnConfig, security_monitor: SecurityMonitor):
        self.config = config
        self.security_monitor = security_monitor
        self._challenges: Dict[str, str] = {}

    def generate_registration_options(
        self,
        user_id: str,
        user_name: str,
        user_display_name: Optional[str] = None
    ) -> Dict[str, Any]:
        """Professional WebAuthn registration options generation"""
        try:
            options = generate_registration_options(
                rp_id=self.config.rp_id,
                rp_name=self.config.rp_name,
                user_id=user_id,
                user_name=user_name,
                user_display_name=user_display_name or user_name,
                authenticator_selection=AuthenticatorSelectionCriteria(
                    user_verification=self.config.user_verification
                )
            )
            
            challenge = bytes_to_base64url(options.challenge)
            self._store_challenge(user_id, challenge, "registration")
            
            return options_to_json(options)
        except Exception as e:
            logger.error(f"Registration options failed: {str(e)}")
            self.security_monitor.log_event("webauthn_registration_failure")
            raise

    def verify_registration(
        self,
        credential: Dict[str, Any],
        expected_challenge: Optional[str]
    ) -> Dict[str, Any]:
        """Secure registration verification with security checks"""
        try:
            credential_parsed = parse_registration_credential_json(credential)
            verification = verify_registration_response(
                credential=RegistrationCredential(
                    **credential_parsed,
                    expected_challenge=base64url_to_bytes(expected_challenge),
                    expected_rp_id=self.config.rp_id,
                    expected_origin=self._get_expected_origin(),
                    require_user_verification=self.config.user_verification == "required"
                )
            
            self.security_monitor.log_event("webauthn_registration_success")
            return {
                "credential_id": bytes_to_base64url(verification.credential_id),
                "public_key": bytes_to_base64url(verification.credential_public_key),
                "sign_count": verification.sign_count
            }
        except Exception as e:
            logger.error(f"Registration verification failed: {str(e)}")
            self.security_monitor.log_event("webauthn_registration_failure")
            raise CredentialVerificationError("Registration verification failed") from e

    def generate_authentication_options(self) -> Dict[str, Any]:
        """Professional authentication options generation"""
        try:
            options = generate_authentication_options(
                rp_id=self.config.rp_id,
                user_verification=self.config.user_verification
            )
            challenge = bytes_to_base64url(options.challenge)
            self._store_challenge("authentication", challenge, "authentication")
            return options_to_json(options)
        except Exception as e:
            logger.error(f"Authentication options failed: {str(e)}")
            self.security_monitor.log_event("webauthn_authentication_failure")
            raise

    def verify_authentication(
        self,
        credential: Dict[str, Any],
        expected_challenge: Optional[str],
        stored_credential: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Secure authentication verification with security checks"""
        try:
            credential_parsed = parse_authentication_credential_json(credential)
            verification = verify_authentication_response(
                credential=AuthenticationCredential(
                    **credential_parsed,
                    expected_challenge=base64url_to_bytes(expected_challenge)),
                credential_public_key=base64url_to_bytes(stored_credential["public_key"]),
                credential_current_sign_count=stored_credential.get("sign_count", 0),
                expected_rp_id=self.config.rp_id,
                expected_origin=self._get_expected_origin()
            )
            
            if verification.new_sign_count <= stored_credential.get("sign_count", 0):
                raise CredentialVerificationError("Potential signature reuse detected")
            
            self.security_monitor.log_event("webauthn_authentication_success")
            return {
                "user_id": stored_credential["user_id"],
                "new_sign_count": verification.new_sign_count
            }
        except Exception as e:
            logger.error(f"Authentication verification failed: {str(e)}")
            self.security_monitor.log_event("webauthn_authentication_failure")
            raise CredentialVerificationError("Authentication verification failed") from e

    def _store_challenge(self, key: str, challenge: str, operation: str):
        """Secure challenge storage with monitoring"""
        self._challenges[f"{operation}_{key}"] = challenge
        self.security_monitor.log_event(
            "challenge_generated",
            metadata={"operation": operation, "length": len(challenge)}
        )

    def _get_expected_origin(self) -> str:
        """Get expected origin based on configuration"""
        return f"https://{self.config.rp_id}" if self.config.rp_id != "localhost" else "http://localhost"
