"""
AFRI SECURE SHIELD - Python Client Library
==========================================

A Python client library for interacting with the AFRI SECURE SHIELD SOC platform.

Installation:
    pip install afri-secure-shield

Usage:
    from afri_secure_shield import AFRISecureShield
    
    client = AFRISecureShield(
        api_key="your-api-key",
        base_url="https://api.afri-secure.com"
    )
    
    # Get alerts
    alerts = client.alerts.list()
    
    # Analyze file
    result = client.sandbox.analyze_file("malware.exe")
"""

import os
import json
import time
import logging
from datetime import datetime, timedelta
from typing import Optional, Dict, List, Any, Union
from dataclasses import dataclass, field
from enum import Enum

import requests
from requests.auth import HTTPBasicAuth
from requests.exceptions import RequestException, Timeout

logger = logging.getLogger(__name__)


class AlertSeverity(Enum):
    """Alert severity levels"""
    CRITICAL = 10
    HIGH = 8
    MEDIUM = 5
    LOW = 3
    INFO = 1


class AlertStatus(Enum):
    """Alert status values"""
    NEW = "new"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


@dataclass
class Alert:
    """Represents a security alert"""
    id: str
    timestamp: str
    severity: int
    confidence: float
    title: str
    description: str
    source: str
    status: str
    mitre_technique: Optional[str] = None
    iocs: List[str] = field(default_factory=list)
    affected_assets: List[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: Dict) -> "Alert":
        return cls(
            id=data.get("id", ""),
            timestamp=data.get("timestamp", ""),
            severity=data.get("severity", 0),
            confidence=data.get("confidence", 0),
            title=data.get("title", ""),
            description=data.get("description", ""),
            source=data.get("source", ""),
            status=data.get("status", "new"),
            mitre_technique=data.get("mitre_technique"),
            iocs=data.get("iocs", []),
            affected_assets=data.get("affected_assets", []),
        )


@dataclass
class LogEntry:
    """Represents a log entry"""
    id: str
    timestamp: str
    source: str
    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    action: Optional[str] = None
    protocol: Optional[str] = None
    user: Optional[str] = None
    hostname: Optional[str] = None
    raw: str = ""

    @classmethod
    def from_dict(cls, data: Dict) -> "LogEntry":
        return cls(
            id=data.get("id", ""),
            timestamp=data.get("timestamp", ""),
            source=data.get("source", ""),
            source_ip=data.get("source_ip"),
            dest_ip=data.get("dest_ip"),
            action=data.get("action"),
            protocol=data.get("protocol"),
            user=data.get("user"),
            hostname=data.get("hostname"),
            raw=data.get("raw", ""),
        )


@dataclass
class AnalysisReport:
    """Sandbox analysis report"""
    id: str
    file_hash: str
    file_name: str
    file_size: int
    file_type: str
    status: str
    verdict: Optional[Dict] = None
    static_analysis: Optional[Dict] = None
    dynamic_analysis: Optional[Dict] = None

    @classmethod
    def from_dict(cls, data: Dict) -> "AnalysisReport":
        return cls(
            id=data.get("id", ""),
            file_hash=data.get("file_hash", ""),
            file_name=data.get("file_name", ""),
            file_size=data.get("file_size", 0),
            file_type=data.get("file_type", ""),
            status=data.get("status", ""),
            verdict=data.get("verdict"),
            static_analysis=data.get("static_analysis"),
            dynamic_analysis=data.get("dynamic_analysis"),
        )


class AFRIException(Exception):
    """Base exception for AFRI SECURE SHIELD client"""
    pass


class APIError(AFRIException):
    """API error response"""
    def __init__(self, message: str, status_code: int = 0, response: Dict = None):
        super().__init__(message)
        self.status_code = status_code
        self.response = response or {}


class RateLimitError(AFRIException):
    """Rate limit exceeded"""
    def __init__(self, retry_after: int = 60):
        self.retry_after = retry_after
        super().__init__(f"Rate limit exceeded. Retry after {retry_after} seconds")


class AFRISecureShield:
    """
    Main client for AFRI SECURE SHIELD SOC Platform.
    
    Example:
        client = AFRISecureShield(
            api_key="your-api-key",
            base_url="https://api.afri-secure.com"
        )
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: str = "http://localhost:8080",
        timeout: int = 30,
        max_retries: int = 3,
        verify_ssl: bool = True,
    ):
        """
        Initialize the AFRI SECURE SHIELD client.
        
        Args:
            api_key: API key for authentication
            base_url: Base URL of the API
            timeout: Request timeout in seconds
            max_retries: Maximum number of retries
            verify_ssl: Whether to verify SSL certificates
        """
        self.api_key = api_key or os.environ.get("AFRI_API_KEY")
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.max_retries = max_retries
        self.verify_ssl = verify_ssl
        
        self.session = requests.Session()
        self.session.headers.update({
            "Content-Type": "application/json",
            "User-Agent": "afri-secure-shield-python/1.0.0",
        })
        
        if self.api_key:
            self.session.headers.update({"Authorization": f"Bearer {self.api_key}"})

    def _request(
        self,
        method: str,
        endpoint: str,
        params: Optional[Dict] = None,
        data: Optional[Dict] = None,
        files: Optional[Dict] = None,
    ) -> Dict:
        """Make an API request with retry logic"""
        url = f"{self.base_url}{endpoint}"
        
        for attempt in range(self.max_retries):
            try:
                if method.upper() == "GET":
                    response = self.session.get(
                        url, params=params, timeout=self.timeout, verify=self.verify_ssl
                    )
                elif method.upper() == "POST":
                    if files:
                        # Multipart request
                        response = self.session.post(
                            url, data=data, files=files, timeout=self.timeout, verify=self.verify_ssl
                        )
                    else:
                        response = self.session.post(
                            url, json=data, timeout=self.timeout, verify=self.verify_ssl
                        )
                elif method.upper() == "PATCH":
                    response = self.session.patch(
                        url, json=data, timeout=self.timeout, verify=self.verify_ssl
                    )
                elif method.upper() == "DELETE":
                    response = self.session.delete(
                        url, timeout=self.timeout, verify=self.verify_ssl
                    )
                else:
                    raise ValueError(f"Unsupported HTTP method: {method}")

                # Handle rate limiting
                if response.status_code == 429:
                    retry_after = int(response.headers.get("Retry-After", 60))
                    if attempt < self.max_retries - 1:
                        time.sleep(retry_after)
                        continue
                    raise RateLimitError(retry_after)

                # Handle other errors
                if response.status_code >= 400:
                    try:
                        error_data = response.json()
                    except:
                        error_data = {"error": response.text}
                    
                    raise APIError(
                        error_data.get("error", "API error"),
                        status_code=response.status_code,
                        response=error_data,
                    )

                return response.json()

            except Timeout:
                if attempt < self.max_retries - 1:
                    time.sleep(2 ** attempt)
                    continue
                raise AFRIException("Request timed out")
            
            except RequestException as e:
                if attempt < self.max_retries - 1:
                    time.sleep(2 ** attempt)
                    continue
                raise AFRIException(f"Request failed: {str(e)}")

        raise AFRIException("Max retries exceeded")

    # ==================== SIEM Operations ====================

    def logs_search(
        self,
        query: str = "*",
        from_time: Optional[str] = None,
        to_time: Optional[str] = None,
        size: int = 100,
    ) -> List[LogEntry]:
        """
        Search logs.
        
        Args:
            query: Search query
            from_time: Start time (ISO format)
            to_time: End time (ISO format)
            size: Maximum results
            
        Returns:
            List of log entries
        """
        params = {"q": query, "size": size}
        if from_time:
            params["from"] = from_time
        if to_time:
            params["to"] = to_time

        results = self._request("GET", "/api/v1/logs", params=params)
        return [LogEntry.from_dict(log) for log in results]

    def logs_ingest(self, logs: List[Dict]) -> Dict:
        """Ingest log entries"""
        return self._request("POST", "/api/v1/logs/ingest", data={"logs": logs})

    # ==================== Alert Operations ====================

    def alerts_list(
        self,
        severity: Optional[int] = None,
        status: Optional[str] = None,
        from_time: Optional[str] = None,
        to_time: Optional[str] = None,
    ) -> List[Alert]:
        """
        List alerts with optional filters.
        
        Args:
            severity: Filter by severity (1-10)
            status: Filter by status
            from_time: Start time
            to_time: End time
            
        Returns:
            List of alerts
        """
        params = {}
        if severity:
            params["severity"] = severity
        if status:
            params["status"] = status
        if from_time:
            params["from"] = from_time
        if to_time:
            params["to"] = to_time

        results = self._request("GET", "/api/v1/alerts", params=params)
        return [Alert.from_dict(alert) for alert in results]

    def alerts_get(self, alert_id: str) -> Alert:
        """Get a specific alert"""
        result = self._request("GET", f"/api/v1/alerts/{alert_id}")
        return Alert.from_dict(result)

    def alerts_update(
        self,
        alert_id: str,
        status: str,
        assigned_to: Optional[str] = None,
    ) -> Alert:
        """
        Update an alert.
        
        Args:
            alert_id: Alert ID
            status: New status
            assigned_to: Analyst to assign to
            
        Returns:
            Updated alert
        """
        data = {"status": status}
        if assigned_to:
            data["assigned_to"] = assigned_to

        result = self._request("PATCH", f"/api/v1/alerts/{alert_id}", data=data)
        return Alert.from_dict(result)

    def alerts_stats(self) -> Dict:
        """Get alert statistics"""
        return self._request("GET", "/api/v1/stats")

    # ==================== Threat Intelligence ====================

    def ti_lookup(self, indicator: str, indicator_type: str) -> Dict:
        """
        Look up threat intelligence for an indicator.
        
        Args:
            indicator: The indicator (IP, domain, hash)
            indicator_type: Type of indicator (ip, domain, hash, url)
            
        Returns:
            Threat intelligence data
        """
        return self._request(
            "GET",
            f"/api/v1/threat-intel/check/{indicator_type}",
            params={"value": indicator},
        )

    def ti_search(
        self,
        query: str,
        indicator_type: Optional[str] = None,
    ) -> List[Dict]:
        """Search threat intelligence"""
        params = {"q": query}
        if indicator_type:
            params["type"] = indicator_type
        return self._request("GET", "/api/v1/threat-intel/search", params=params)

    def ti_cves_recent(self, days: int = 7) -> List[Dict]:
        """Get recent CVEs"""
        return self._request("GET", "/api/v1/threat-intel/cves/recent", params={"days": days})

    def ti_actors(self) -> List[Dict]:
        """Get threat actors"""
        return self._request("GET", "/api/v1/threat-intel/actors")

    # ==================== Sandbox ====================

    def sandbox_analyze(self, file_path: str) -> AnalysisReport:
        """
        Submit a file for sandbox analysis.
        
        Args:
            file_path: Path to file to analyze
            
        Returns:
            Analysis report
        """
        with open(file_path, "rb") as f:
            files = {"file": (os.path.basename(file_path), f)}
            result = self._request(
                "POST",
                "/api/v1/sandbox/analyze",
                data={},
                files=files,
            )
        return AnalysisReport.from_dict(result)

    def sandbox_report(self, report_id: str) -> AnalysisReport:
        """Get a sandbox analysis report"""
        result = self._request("GET", f"/api/v1/sandbox/reports/{report_id}")
        return AnalysisReport.from_dict(result)

    def sandbox_reports_list(self, limit: int = 50) -> List[AnalysisReport]:
        """List recent sandbox reports"""
        results = self._request("GET", "/api/v1/sandbox/reports", params={"limit": limit})
        return [AnalysisReport.from_dict(r) for r in results]

    # ==================== SOAR ====================

    def soar_playbooks_list(self) -> List[Dict]:
        """List available playbooks"""
        return self._request("GET", "/api/v1/soar/playbooks")

    def soar_playbook_run(self, playbook_id: str, trigger_data: Dict) -> Dict:
        """Run a playbook manually"""
        return self._request(
            "POST",
            f"/api/v1/soar/playbooks/{playbook_id}/run",
            data=trigger_data,
        )

    def soar_executions_list(
        self,
        playbook_id: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[Dict]:
        """List playbook executions"""
        params = {}
        if playbook_id:
            params["playbook_id"] = playbook_id
        if status:
            params["status"] = status
        return self._request("GET", "/api/v1/soar/executions", params=params)

    # ==================== Fraud Detection ====================

    def fraud_evaluate(
        self,
        user_id: str,
        amount: float,
        transaction_type: str,
        **kwargs,
    ) -> Dict:
        """
        Evaluate a transaction for fraud.
        
        Args:
            user_id: User ID
            amount: Transaction amount
            transaction_type: Type (payment, transfer, withdrawal, refund)
            **kwargs: Additional transaction data
            
        Returns:
            Fraud evaluation result
        """
        data = {
            "id": f"txn_{int(time.time() * 1000)}",
            "timestamp": datetime.now().isoformat(),
            "user_id": user_id,
            "amount": amount,
            "type": transaction_type,
            **kwargs,
        }
        return self._request("POST", "/api/v1/fraud/evaluate", data=data)

    def fraud_alerts(self, status: Optional[str] = None) -> List[Dict]:
        """Get fraud alerts"""
        params = {}
        if status:
            params["status"] = status
        return self._request("GET", "/api/v1/fraud/alerts", params=params)

    def fraud_risk_score(self, user_id: str) -> Dict:
        """Get user risk score"""
        return self._request("GET", f"/api/v1/fraud/risk/{user_id}")

    # ==================== Academy ====================

    def academy_courses(self) -> List[Dict]:
        """List available courses"""
        return self._request("GET", "/api/v1/academy/courses")

    def academy_enroll(self, user_id: str, course_id: str) -> Dict:
        """Enroll in a course"""
        return self._request(
            "POST",
            "/api/v1/academy/enroll",
            data={"user_id": user_id, "course_id": course_id},
        )

    def academy_progress(
        self,
        enrollment_id: str,
        lesson_id: str,
        time_spent: int,
    ) -> Dict:
        """Update lesson progress"""
        return self._request(
            "POST",
            "/api/v1/academy/progress",
            data={
                "enrollment_id": enrollment_id,
                "lesson_id": lesson_id,
                "time_spent": time_spent,
            },
        )

    # ==================== WebSocket ====================

    def ws_connect(
        self,
        on_message: callable,
        on_connect: Optional[callable] = None,
        on_error: Optional[callable] = None,
    ):
        """
        Connect to WebSocket for real-time notifications.
        
        Args:
            on_message: Callback for messages
            on_connect: Callback on connect
            on_error: Callback on error
            
        Returns:
            WebSocket connection
        """
        try:
            import websocket
            
            ws_url = self.base_url.replace("http", "ws").rstrip("/") + ":8087"
            
            ws = websocket.WebSocketApp(
                ws_url,
                on_message=on_message,
                on_open=on_connect,
                on_error=on_error,
            )
            
            return ws
        except ImportError:
            raise AFRIException("websocket-client not installed. Run: pip install websocket-client")

    # ==================== Context Manager ====================

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.session.close()


# ==================== Convenience Functions ====================

def create_client(
    api_key: Optional[str] = None,
    base_url: str = "http://localhost:8080",
    **kwargs,
) -> AFRISecureShield:
    """Create an AFRI SECURE SHIELD client"""
    return AFRISecureShield(api_key=api_key, base_url=base_url, **kwargs)


def quick_alerts(
    severity: int = 5,
    hours: int = 24,
    **kwargs,
) -> List[Alert]:
    """
    Quick function to get recent alerts.
    
    Example:
        alerts = quick_alerts(severity=8, hours=12)
    """
    client = AFRISecureShield(**kwargs)
    from_time = (datetime.now() - timedelta(hours=hours)).isoformat()
    return client.alerts_list(severity=severity, from_time=from_time)


def quick_scan(file_path: str, **kwargs) -> AnalysisReport:
    """
    Quick function to scan a file.
    
    Example:
        report = quick_scan("malware.exe")
    """
    client = AFRISecureShield(**kwargs)
    return client.sandbox_analyze(file_path)
