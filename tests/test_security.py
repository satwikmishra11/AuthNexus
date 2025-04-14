import time
import pytest
from authnexus import SecurityMonitor, SecurityConfig

@pytest.fixture
def security_monitor():
    return SecurityMonitor(config=SecurityConfig(
        risk_threshold=0.7,
        max_failed_attempts=3
    ))

class TestRiskAnalysis:
    def test_risk_calculation(self, security_monitor):
        """Test basic risk score calculation"""
        security_monitor.log_event("login_failure", {
            "ip": "192.168.1.1",
            "user_agent": "test-agent"
        })
        score = security_monitor.calculate_risk(
            "192.168.1.1", 
            "test-agent"
        )
        assert 0.4 <= score <= 0.5

    def test_high_risk_scenario(self, security_monitor):
        """Test threshold breach detection"""
        for _ in range(4):
            security_monitor.log_event("login_failure", {
                "ip": "10.0.0.1",
                "user_agent": "suspicious-bot"
            })
        
        assert security_monitor.check_anomalies({
            "client_ip": "10.0.0.1",
            "user_agent": "suspicious-bot"
        }) is True

    def test_velocity_analysis(self, security_monitor, mocker):
        """Test IP velocity detection"""
        mocker.patch("time.time", return_value=0)
        security_monitor.log_event("login_attempt", {
            "ip": "192.168.1.2",
            "user_agent": "legitimate-client"
        })
        
        mocker.patch("time.time", return_value=60)  # 1 minute later
        security_monitor.log_event("login_attempt", {
            "ip": "192.168.1.2",
            "user_agent": "legitimate-client"
        })
        
        score = security_monitor.calculate_risk(
            "192.168.1.2", 
            "legitimate-client"
        )
        assert score > 0.3

class TestSecurityMonitoring:
    def test_event_logging(self, security_monitor):
        """Test event storage and retrieval"""
        security_monitor.log_event("test_event", {"key": "value"})
        report = security_monitor.generate_report()
        assert report["total_events"] == 1
        assert "test_event" in report["common_event_types"]

    def test_report_generation(self, security_monitor):
        """Test security report contents"""
        for _ in range(5):
            security_monitor.log_event("login_failure", {
                "ip": "10.0.0.5",
                "user_agent": "malicious-actor"
            })
        
        report = security_monitor.generate_report()
        assert report["high_risk_events"] >= 5
        assert "10.0.0.5" in [ip["ip"] for ip in report["top_risky_ips"]]

    def test_blacklist_detection(self, security_monitor, mocker):
        """Test integration with threat intelligence"""
        mocker.patch(
            "authnexus.core.security_monitor.SecurityMonitor._is_ip_blacklisted",
            return_value=True
        )
        assert security_monitor.check_anomalies({
            "client_ip": "1.2.3.4",
            "user_agent": "normal-client"
        }) is True
