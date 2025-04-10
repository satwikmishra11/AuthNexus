from typing import Optional, Dict, Any
from fastapi import Request, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from starlette.concurrency import run_in_threadpool
from pydantic import BaseModel
from ..core import AuthNexus, SecurityMonitor, WebAuthnManager
from ..exceptions import (
    InvalidTokenError,
    SecurityThresholdExceeded,
    CredentialVerificationError
)

class AuthNexusFastAPIConfig(BaseModel):
    """Professional configuration model for FastAPI integration"""
    auto_error: bool = True
    security_header: str = "X-AuthNexus-Security-Report"
    enable_webauthn_routes: bool = True
    rate_limit: str = "100/minute"

class AuthNexusFastAPI:
    def __init__(self, auth_nexus: AuthNexus, config: Optional[AuthNexusFastAPIConfig] = None):
        """Professional FastAPI integration constructor"""
        self.auth = auth_nexus
        self.config = config or AuthNexusFastAPIConfig()
        self.security_scheme = HTTPBearer(auto_error=self.config.auto_error)
        
        if self.config.enable_webauthn_routes:
            self.webauthn = WebAuthnIntegration(auth_nexus)

    async def get_current_user(
        self, 
        request: Request,
        credentials: Optional[HTTPAuthorizationCredentials] = Depends(HTTPBearer(auto_error=False))
    ) -> Dict[str, Any]:
        """Professional dependency for user extraction"""
        if not credentials:
            if self.config.auto_error:
                raise HTTPException(401, "Missing authorization header")
            return None

        try:
            token = credentials.credentials
            payload = await run_in_threadpool(self.auth.verify_token, token)
            
            # Security monitoring hook
            await self._check_request_security(request, payload)
            
            return payload
        except InvalidTokenError as e:
            raise HTTPException(401, "Invalid token") from e
        except SecurityThresholdExceeded as e:
            raise HTTPException(403, str(e)) from e

    async def _check_request_security(self, request: Request, payload: Dict):
        """Enterprise-grade security checks"""
        security_report = {
            "risk_score": self.auth.security_monitor.calculate_risk(
                client_ip=request.client.host,
                user_agent=request.headers.get("user-agent"),
                user_context=payload
            ),
            "anomalies": await run_in_threadpool(
                self.auth.security_monitor.check_anomalies,
                payload
            )
        }

        request.state.security_report = security_report
        
        if security_report["risk_score"] > 0.85:
            raise SecurityThresholdExceeded(
                f"High risk activity detected: {security_report}"
            )

        request.headers.append(
            self.config.security_header,
            str(security_report)
        )

    def create_router(self):
        """Professional router factory for WebAuthn endpoints"""
        from fastapi import APIRouter
        
        router = APIRouter(
            tags=["authentication"],
            dependencies=[Depends(self.rate_limiter)],
            responses={
                401: {"description": "Unauthorized"},
                403: {"description": "Forbidden"}
            }
        )

        if self.config.enable_webauthn_routes:
            @router.post("/webauthn/register/start")
            async def start_registration(request: Request):
                return await self.webauthn.handle_registration_start(request)

            @router.post("/webauthn/register/complete")
            async def complete_registration(request: Request):
                return await self.webauthn.handle_registration_complete(request)

            @router.post("/webauthn/login/start")
            async def start_login(request: Request):
                return await self.webauthn.handle_login_start(request)

            @router.post("/webauthn/login/complete")
            async def complete_login(request: Request):
                return await self.webauthn.handle_login_complete(request)

        return router

    @property
    def rate_limiter(self):
        """Professional rate limiting dependency"""
        from fastapi_limiter.depends import RateLimiter
        return Depends(RateLimiter(times=self.config.rate_limit))

class WebAuthnIntegration:
    """Professional WebAuthn route handler implementation"""
    def __init__(self, auth_nexus: AuthNexus):
        self.auth = auth_nexus
        self.webauthn = auth_nexus.webauthn

    async def handle_registration_start(self, request: Request):
        """Secure registration initialization"""
        try:
            user = await self._get_user_from_request(request)
            options = await run_in_threadpool(
                self.webauthn.generate_registration_options,
                user_id=user.id,
                user_name=user.username,
                user_display_name=user.display_name
            )
            request.session["webauthn_challenge"] = options.challenge
            return options
        except Exception as e:
            self.auth.security_monitor.log_event("webauthn_start_failure")
            raise HTTPException(400, "Registration initialization failed") from e

    async def handle_registration_complete(self, request: Request):
        """Professional credential verification"""
        try:
            credential = await request.json()
            verification = await run_in_threadpool(
                self.webauthn.verify_registration,
                credential=credential,
                expected_challenge=request.session.pop("webauthn_challenge", None)
            )
            await self._store_credential(verification)
            return {"status": "success"}
        except CredentialVerificationError as e:
            self.auth.security_monitor.log_event("webauthn_verification_failure")
            raise HTTPException(400, "Credential verification failed") from e

    async def _store_credential(self, verification):
        """Secure credential storage placeholder"""
        # Implement your secure storage here
        pass

    async def handle_login_start(self, request: Request):
        """Passwordless authentication initialization"""
        try:
            options = await run_in_threadpool(
                self.webauthn.generate_authentication_options
            )
            request.session["auth_challenge"] = options.challenge
            return options
        except Exception as e:
            self.auth.security_monitor.log_event("webauthn_login_start_failure")
            raise HTTPException(400, "Login initialization failed") from e

    async def handle_login_complete(self, request: Request):
        """Professional authentication verification"""
        try:
            credential = await request.json()
            verification = await run_in_threadpool(
                self.webauthn.verify_authentication,
                credential=credential,
                expected_challenge=request.session.pop("auth_challenge", None),
                stored_credential=await self._get_stored_credential(credential["id"])
            )
            return {"token": self.auth.create_token(verification.user_id)}
        except CredentialVerificationError as e:
            self.auth.security_monitor.log_event("webauthn_login_failure")
            raise HTTPException(401, "Authentication failed") from e

    async def _get_stored_credential(self, credential_id: str):
        """Secure credential retrieval placeholder"""
        # Implement your credential lookup here
        return None
