__version__ = "0.1.0"

from .core.auth_manager import AuthNexus
from .core.webauthn import WebAuthnManager
from .core.security_monitor import SecurityMonitor, SecurityConfig
from .exceptions import (
    InvalidTokenError,
    SecurityThresholdExceeded,
    CredentialVerificationError
)

# Public API
__all__ = [
    'AuthNexus',
    'WebAuthnManager',
    'SecurityMonitor',
    'SecurityConfig',
    'InvalidTokenError',
    'SecurityThresholdExceeded',
    'CredentialVerificationError'
]

# Initialize package logging
import logging
logging.getLogger(__name__).addHandler(logging.NullHandler())

def init_app(app):
    """Professional Flask extension initialization shortcut"""
    from .integrations.flask import AuthNexusFlask
    return AuthNexusFlask(app)
