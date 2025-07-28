#!/usr/bin/env python3
"""
Monitoring, metrics, and observability for ValhallaBot2
Provides comprehensive monitoring capabilities
"""

import time
import asyncio
from typing import Dict, Any, Optional, List
from collections import defaultdict, deque
from datetime import datetime, timezone
import logging

logger = logging.getLogger(__name__)

class MetricsCollector:
    """Collects and manages application metrics"""
    
    def __init__(self):
        self.start_time = time.time()
        self.counters: Dict[str, int] = defaultdict(int)
        self.gauges: Dict[str, float] = {}
        self.histograms: Dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))
        self.labels: Dict[str, Dict[str, Any]] = defaultdict(dict)
    
    def increment_counter(self, name: str, value: int = 1, labels: Optional[Dict[str, str]] = None):
        """Increment a counter metric"""
        key = self._make_key(name, labels)
        self.counters[key] += value
        if labels:
            self.labels[key] = labels
    
    def set_gauge(self, name: str, value: float, labels: Optional[Dict[str, str]] = None):
        """Set a gauge metric"""
        key = self._make_key(name, labels)
        self.gauges[key] = value
        if labels:
            self.labels[key] = labels
    
    def record_histogram(self, name: str, value: float, labels: Optional[Dict[str, str]] = None):
        """Record a histogram value"""
        key = self._make_key(name, labels)
        self.histograms[key].append((time.time(), value))
        if labels:
            self.labels[key] = labels
    
    def _make_key(self, name: str, labels: Optional[Dict[str, str]] = None) -> str:
        """Create a unique key for metrics with labels"""
        if not labels:
            return name
        label_str = ",".join(f"{k}={v}" for k, v in sorted(labels.items()))
        return f"{name}{{{label_str}}}"
    
    def get_metrics_summary(self) -> Dict[str, Any]:
        """Get a summary of all metrics"""
        return {
            "uptime_seconds": time.time() - self.start_time,
            "counters": dict(self.counters),
            "gauges": dict(self.gauges),
            "histogram_counts": {k: len(v) for k, v in self.histograms.items()}
        }

class PerformanceMonitor:
    """Monitor performance of operations"""
    
    def __init__(self):
        self.active_requests: Dict[str, float] = {}
        self.request_history: deque = deque(maxlen=1000)
    
    def start_request(self, request_id: str, operation: str):
        """Start monitoring a request"""
        self.active_requests[request_id] = {
            'start_time': time.time(),
            'operation': operation
        }
    
    def end_request(self, request_id: str, success: bool):
        """End monitoring a request"""
        if request_id in self.active_requests:
            request_data = self.active_requests.pop(request_id)
            duration = time.time() - request_data['start_time']
            
            self.request_history.append({
                'operation': request_data['operation'],
                'duration': duration,
                'success': success,
                'timestamp': time.time()
            })
    
    def get_performance_stats(self) -> Dict[str, Any]:
        """Get performance statistics"""
        if not self.request_history:
            return {"no_data": True}
        
        recent_requests = list(self.request_history)
        total_requests = len(recent_requests)
        successful_requests = sum(1 for r in recent_requests if r['success'])
        
        durations = [r['duration'] for r in recent_requests]
        avg_duration = sum(durations) / len(durations) if durations else 0
        
        return {
            "total_requests": total_requests,
            "success_rate": successful_requests / total_requests if total_requests > 0 else 0,
            "average_duration_seconds": avg_duration,
            "active_requests": len(self.active_requests)
        }

class HealthChecker:
    """Health check utilities"""
    
    def __init__(self):
        self.health_checks: Dict[str, callable] = {}
        self.last_check_results: Dict[str, Dict[str, Any]] = {}
    
    def register_check(self, name: str, check_func: callable):
        """Register a health check function"""
        self.health_checks[name] = check_func
    
    async def run_checks(self) -> Dict[str, Dict[str, Any]]:
        """Run all registered health checks"""
        results = {}
        for name, check_func in self.health_checks.items():
            try:
                start_time = time.time()
                if asyncio.iscoroutinefunction(check_func):
                    result = await check_func()
                else:
                    result = check_func()
                
                duration = time.time() - start_time
                results[name] = {
                    "status": "healthy" if result else "unhealthy",
                    "duration_seconds": duration,
                    "timestamp": datetime.utcnow().isoformat()
                }
            except Exception as e:
                results[name] = {
                    "status": "error",
                    "error": str(e),
                    "timestamp": datetime.utcnow().isoformat()
                }
        
        self.last_check_results = results
        return results
    
    def get_overall_health(self) -> Dict[str, Any]:
        """Get overall health status"""
        if not self.last_check_results:
            return {"status": "unknown", "message": "No health checks run yet"}
        
        all_healthy = all(
            result.get("status") == "healthy" 
            for result in self.last_check_results.values()
        )
        
        return {
            "status": "healthy" if all_healthy else "unhealthy",
            "checks": self.last_check_results,
            "timestamp": datetime.utcnow().isoformat()
        }

class MonitoringSystem:
    """Main monitoring system that coordinates all monitoring components"""
    
    def __init__(self):
        self.metrics = MetricsCollector()
        self.performance_monitor = PerformanceMonitor()
        self.health_checker = HealthChecker()
        self.alerts: List[Dict[str, Any]] = []
    
    def add_alert(self, level: str, message: str, details: Optional[Dict[str, Any]] = None):
        """Add an alert to the monitoring system"""
        alert = {
            "level": level,
            "message": message,
            "details": details or {},
            "timestamp": datetime.utcnow().isoformat()
        }
        self.alerts.append(alert)
        
        # Keep only last 100 alerts
        if len(self.alerts) > 100:
            self.alerts = self.alerts[-100:]
        
        logger.warning(f"Alert [{level}]: {message}")
    
    def get_status_report(self) -> Dict[str, Any]:
        """Get comprehensive status report"""
        return {
            "timestamp": datetime.utcnow().isoformat(),
            "metrics": self.metrics.get_metrics_summary(),
            "performance": self.performance_monitor.get_performance_stats(),
            "health": self.health_checker.get_overall_health(),
            "recent_alerts": self.alerts[-10:] if self.alerts else []
        }

# Global monitoring instance
monitoring = MonitoringSystem()
