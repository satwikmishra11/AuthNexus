import time
from typing import Dict, Optional, List
from pydantic import BaseModel
import logging
from dataclasses import dataclass

logger = logging.getLogger(__name__)

class SecurityEvent(BaseModel):
    timestamp: float
    event_type: str
    metadata: dict = {}
    risk_score: float = 0.0

class RiskProfile(BaseModel):
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    failed_attempts: int = 0
    last_attempt: float = 0.0
    locations: List[str] = []

@dataclass
class SecurityConfig:
    risk_threshold: float = 0.8
    ip_velocity_window: int = 300  # 5 minutes
    max_failed_attempts: int = 5

class SecurityMonitor:
    def __init__(self, config: Optional[SecurityConfig] = None):
        self.config = config or SecurityConfig()
        self.events: List[SecurityEvent] = []
        self.risk_profiles: Dict[str, RiskProfile] = {}

    def calculate_risk(self, client_ip: str, user_agent: str) -> float:
        """Professional risk scoring engine"""
        profile = self._get_or_create_profile(client_ip, user_agent)
        risk = 0.0
        
        # Failed attempts risk
        risk += min(profile.failed_attempts / self.config.max_failed_attempts, 1.0) * 0.4
        
        # Velocity check
        if time.time() - profile.last_attempt < self.config.ip_velocity_window:
            risk += 0.3
            
        # User agent anomalies
        if "bot" in (user_agent or "").lower():
            risk += 0.2
            
        return min(risk, 1.0)

    def check_anomalies(self, request_data: dict) -> bool:
        """Enterprise-grade anomaly detection"""
        client_ip = request_data.get("client_ip", "")
        user_agent = request_data.get("user_agent", "")
        
        # Check IP reputation
        if self._is_ip_blacklisted(client_ip):
            return True
            
        # Check risk score
        if self.calculate_risk(client_ip, user_agent) > self.config.risk_threshold:
            return True
            
        return False

    def log_event(self, event_type: str, metadata: Optional[dict] = None):
        """Professional event logging with risk assessment"""
        event = SecurityEvent(
            timestamp=time.time(),
            event_type=event_type,
            metadata=metadata or {},
            risk_score=self.calculate_risk(
                metadata.get("ip", ""),
                metadata.get("user_agent", "")
            ) if metadata else 0.0
        )
        self.events.append(event)
        
        # Update risk profiles
        if "ip" in metadata and "user_agent" in metadata:
            profile = self._get_or_create_profile(
                metadata["ip"],
                metadata["user_agent"]
            )
            if "failure" in event_type:
                profile.failed_attempts += 1
            profile.last_attempt = event.timestamp

        logger.info(f"Security event: {event_type} (Risk: {event.risk_score:.2f})")

    def generate_report(self, hours: int = 24) -> dict:
        """Professional security report generation"""
        cutoff = time.time() - (hours * 3600)
        recent_events = [e for e in self.events if e.timestamp > cutoff]
        
        return {
            "total_events": len(recent_events),
            "high_risk_events": sum(1 for e in recent_events if e.risk_score > 0.7),
            "common_event_types": self._count_event_types(recent_events),
            "top_risky_ips": self._get_top_risky_ips(recent_events),
            "risk_trends": self._calculate_risk_trends(recent_events)
        }

    def _get_or_create_profile(self, ip: str, user_agent: str) -> RiskProfile:
        key = f"{ip}_{user_agent}"
        if key not in self.risk_profiles:
            self.risk_profiles[key] = RiskProfile(
                ip_address=ip,
                user_agent=user_agent
            )
        return self.risk_profiles[key]

    def _is_ip_blacklisted(self, ip: str) -> bool:
        # Integrate with external threat intelligence feeds
        return False

    def _count_event_types(self, events: List[SecurityEvent]) -> Dict[str, int]:
        counts = {}
        for event in events:
            counts[event.event_type] = counts.get(event.event_type, 0) + 1
        return counts

    def _get_top_risky_ips(self, events: List[SecurityEvent]) -> List[dict]:
        ip_scores = {}
        for event in events:
            ip = event.metadata.get("ip")
            if ip:
                ip_scores[ip] = ip_scores.get(ip, 0.0) + event.risk_score
        return sorted(
            [{"ip": k, "score": v} for k, v in ip_scores.items()],
            key=lambda x: x["score"],
            reverse=True
        )[:5]

    def _calculate_risk_trends(self, events: List[SecurityEvent]) -> List[dict]:
        # Implement time-series risk analysis
        return []
