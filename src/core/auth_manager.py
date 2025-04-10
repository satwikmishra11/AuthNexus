from typing import Optional
from pydantic import BaseModel
import jwt
from datetime import datetime, timedelta

class AuthConfig(BaseModel):
    secret_key: str
    algorithm: str = "HS256"
    token_expiry: int = 3600  # 1 hour
    webauthn_timeout: int = 300  # 5 minutes

class AuthNexus:
    def __init__(self, config: AuthConfig):
        self.config = config
        self.security_monitor = SecurityMonitor()

    def create_token(self, user_id: str, metadata: dict) -> str:
        """JWT token generation with security checks"""
        payload = {
            "sub": user_id,
            "exp": datetime.utcnow() + timedelta(seconds=self.config.token_expiry),
            "iss": "authnexus",
            **metadata
        }
        return jwt.encode(payload, self.config.secret_key, algorithm=self.config.algorithm)

    def verify_token(self, token: str) -> Optional[dict]:
        """Secure token verification with anomaly detection"""
        try:
            payload = jwt.decode(
                token,
                self.config.secret_key,
                algorithms=[self.config.algorithm]
            )
            
            if self.security_monitor.check_anomalies(payload):
                raise SecurityException("Suspicious token activity")
                
            return payload
        except jwt.PyJWTError:
            return None

class SecurityMonitor:
    def check_anomalies(self, payload: dict) -> bool:
        """Basic anomaly detection (extend for enterprise use)"""
        if payload.get('iss') != 'authnexus':
            return True
        if datetime.utcfromtimestamp(payload['exp']) < datetime.utcnow():
            return True
        return False
