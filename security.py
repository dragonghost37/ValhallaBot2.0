#!/usr/bin/env python3
"""
Security utilities and middleware for ValhallaBot2
Provides authentication, authorization, and security monitoring
"""

import hashlib
import hmac
import time
import ssl
from typing import Dict, Any, Optional, List
from dataclasses import dataclass
import logging

logger = logging.getLogger(__name__)

@dataclass
class SecurityConfig:
    """Security configuration"""
    webhook_secret: str
    rate_limit_enabled: bool = True
    max_requests_per_minute: int = 60
    enable_ip_whitelist: bool = False
    allowed_ips: List[str] = None
    
    def __post_init__(self):
        if self.allowed_ips is None:
            self.allowed_ips = []

class SecurityMiddleware:
    """Security middleware for request processing"""
    
    def __init__(self, config: SecurityConfig):
        self.config = config
        self.request_counts: Dict[str, List[float]] = {}
        self.blocked_ips: Dict[str, float] = {}
    
    def check_rate_limit(self, client_ip: str) -> bool:
        """Check if client IP is within rate limits"""
        if not self.config.rate_limit_enabled:
            return True
        
        now = time.time()
        
        # Clean old requests
        if client_ip in self.request_counts:
            self.request_counts[client_ip] = [
                req_time for req_time in self.request_counts[client_ip]
                if now - req_time < 60  # Keep last minute
            ]
        else:
            self.request_counts[client_ip] = []
        
        # Check rate limit
        if len(self.request_counts[client_ip]) >= self.config.max_requests_per_minute:
            self.blocked_ips[client_ip] = now
            return False
        
        # Add current request
        self.request_counts[client_ip].append(now)
        return True
    
    def check_ip_whitelist(self, client_ip: str) -> bool:
        """Check if IP is in whitelist (if enabled)"""
        if not self.config.enable_ip_whitelist:
            return True
        
        return client_ip in self.config.allowed_ips
    
    def is_blocked(self, client_ip: str) -> bool:
        """Check if IP is currently blocked"""
        if client_ip in self.blocked_ips:
            block_time = self.blocked_ips[client_ip]
            if time.time() - block_time < 300:  # 5 minute block
                return True
            else:
                del self.blocked_ips[client_ip]
        return False

class WebhookSecurity:
    """Webhook security utilities"""
    
    def __init__(self, secret: str):
        self.secret = secret.encode('utf-8') if isinstance(secret, str) else secret
    
    def verify_signature(self, payload: bytes, signature: str) -> bool:
        """Verify webhook signature"""
        if not signature or not self.secret:
            return False
        
        try:
            # Twitch uses HMAC-SHA256 with format "sha256=<hash>"
            if signature.startswith('sha256='):
                expected_signature = signature
                computed_signature = 'sha256=' + hmac.new(
                    self.secret,
                    payload,
                    hashlib.sha256
                ).hexdigest()
                
                return hmac.compare_digest(expected_signature, computed_signature)
            
            return False
        except Exception as e:
            logger.error(f"Signature verification error: {e}")
            return False
    
    def generate_signature(self, payload: bytes) -> str:
        """Generate webhook signature"""
        signature = hmac.new(
            self.secret,
            payload,
            hashlib.sha256
        ).hexdigest()
        return f"sha256={signature}"

class SecurityAuditor:
    """Security event auditing and monitoring"""
    
    def __init__(self):
        self.security_events: List[Dict[str, Any]] = []
        self.threat_counts: Dict[str, int] = {}
    
    def log_security_event(self, event_type: str, client_ip: str, details: Optional[Dict[str, Any]] = None):
        """Log security event"""
        event = {
            "event_type": event_type,
            "client_ip": client_ip,
            "timestamp": time.time(),
            "details": details or {}
        }
        
        self.security_events.append(event)
        self.threat_counts[event_type] = self.threat_counts.get(event_type, 0) + 1
        
        # Keep only last 10000 events
        if len(self.security_events) > 10000:
            self.security_events = self.security_events[-10000:]
        
        logger.warning(f"Security event [{event_type}] from {client_ip}: {details}")
    
    def get_security_summary(self) -> Dict[str, Any]:
        """Get security summary"""
        recent_events = [
            e for e in self.security_events 
            if time.time() - e["timestamp"] < 3600  # Last hour
        ]
        
        return {
            "events_last_hour": len(recent_events),
            "threat_types": dict(self.threat_counts),
            "recent_events": recent_events[-10:] if recent_events else []
        }

class SSLContextManager:
    """SSL context management"""
    
    @staticmethod
    def create_ssl_context() -> ssl.SSLContext:
        """Create secure SSL context"""
        context = ssl.create_default_context()
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        
        # Set secure protocols
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        
        # Set secure ciphers
        context.set_ciphers('ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS')
        
        return context

def create_security_config() -> SecurityConfig:
    """Create security configuration from environment"""
    import os
    
    return SecurityConfig(
        webhook_secret=os.getenv('WEBHOOK_SECRET', os.getenv('TWITCH_EVENTSUB_SECRET', '')),
        rate_limit_enabled=os.getenv('RATE_LIMIT_ENABLED', 'true').lower() == 'true',
        max_requests_per_minute=int(os.getenv('MAX_REQUESTS_PER_MINUTE', '60')),
        enable_ip_whitelist=os.getenv('ENABLE_IP_WHITELIST', 'false').lower() == 'true',
        allowed_ips=os.getenv('ALLOWED_IPS', '').split(',') if os.getenv('ALLOWED_IPS') else []
    )

# Global instances
security_auditor = SecurityAuditor()
