from typing import Optional, Dict, Any, Callable
from flask import Flask, Request, current_app, Blueprint, jsonify
from werkzeug.exceptions import Unauthorized, Forbidden
from ..core import AuthNexus, SecurityMonitor, WebAuthnManager
from ..exceptions import InvalidTokenError, SecurityThresholdExceeded

class AuthNexusFlask:
    """Professional Flask integration for AuthNexus"""
    
    def __init__(self, app: Optional[Flask] = None):
        self.app = app
        self.auth: Optional[AuthNexus] = None
        self.webauthn: Optional[WebAuthnManager] = None
        self.security_monitor: Optional[SecurityMonitor] = None
        
        if app is not None:
            self.init_app(app)

    def init_app(self, app: Flask):
        """Professional Flask extension initialization"""
        self.app = app
        app.config.setdefault('AUTHNEXUS_SECRET', app.config['SECRET_KEY'])
        app.config.setdefault('AUTHNEXUS_TOKEN_EXPIRY', 3600)
        
        self.auth = AuthNexus(
            secret_key=app.config['AUTHNEXUS_SECRET'],
            token_expiry=app.config['AUTHNEXUS_TOKEN_EXPIRY']
        )
        self.webauthn = self.auth.webauthn
        self.security_monitor = self.auth.security_monitor
        
        # Register middleware and blueprints
        app.before_request(self._security_middleware)
        app.register_blueprint(self._create_auth_blueprint())

    def _create_auth_blueprint(self) -> Blueprint:
        """Professional blueprint for authentication routes"""
        bp = Blueprint('auth', __name__, url_prefix='/auth')
        
        @bp.route('/token', methods=['POST'])
        def login():
            # Implement actual login logic
            return jsonify({"token": self.auth.create_token("user_id")})
            
        if self.webauthn:
            @bp.route('/webauthn/register/start', methods=['POST'])
            def webauthn_register_start():
                # WebAuthn registration initialization
                return jsonify(self.webauthn.generate_registration_options(...))
                
            @bp.route('/webauthn/register/complete', methods=['POST'])
            def webauthn_register_complete():
                # WebAuthn registration completion
                return jsonify({"status": "success"})
        
        return bp

    def token_required(self, f: Callable) -> Callable:
        """Professional decorator for token-protected routes"""
        def wrapper(*args, **kwargs):
            token = self._get_token_from_request()
            try:
                user = self.auth.verify_token(token)
                if self.security_monitor.check_anomalies(user):
                    raise SecurityThresholdExceeded()
                return f(user=user, *args, **kwargs)
            except InvalidTokenError:
                raise Unauthorized("Invalid token")
            except SecurityThresholdExceeded:
                raise Forbidden("Security policy violated")
        return wrapper

    def _get_token_from_request(self) -> str:
        """Professional token extraction"""
        auth_header = request.headers.get('Authorization', '')
        if not auth_header.startswith('Bearer '):
            raise Unauthorized("Missing or invalid authorization header")
        return auth_header.split(' ')[1]

    def _security_middleware(self):
        """Professional security middleware"""
        request.environ['authnexus.risk_score'] = self.security_monitor.calculate_risk(
            client_ip=request.remote_addr,
            user_agent=request.headers.get('User-Agent')
        )

    @property
    def rate_limiter(self) -> Callable:
        """Professional rate limiting decorator"""
        from flask_limiter import Limiter
        return Limiter(
            self.app,
            key_func=lambda: request.remote_addr,
            default_limits=["200 per day", "50 per hour"]
        ).limit

    def create_token(self, user_id: str, metadata: Dict = None) -> str:
        """Token generation shortcut"""
        return self.auth.create_token(user_id, metadata)

    def verify_token(self, token: str) -> Dict:
        """Token verification shortcut"""
        return self.auth.verify_token(token)
