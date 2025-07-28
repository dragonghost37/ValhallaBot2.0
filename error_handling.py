#!/usr/bin/env python3
"""
Error handling, retry logic, and database management for ValhallaBot2
Provides robust error handling and database connection management
"""

import asyncio
import asyncpg
import aiohttp
import time
import logging
from typing import Optional, Dict, Any, Callable, List
from dataclasses import dataclass
from enum import Enum
from functools import wraps
import traceback

logger = logging.getLogger(__name__)

class ErrorSeverity(Enum):
    """Error severity levels"""
    LOW = "low"
    MEDIUM = "medium" 
    HIGH = "high"
    CRITICAL = "critical"

class DatabaseError(Exception):
    """Database-related errors"""
    pass

class APIError(Exception):
    """API-related errors"""
    pass

@dataclass
class RetryConfig:
    """Configuration for retry logic"""
    max_attempts: int = 3
    base_delay: float = 1.0
    max_delay: float = 60.0
    exponential_base: float = 2.0
    jitter: bool = True

class CircuitBreaker:
    """Circuit breaker pattern implementation"""
    
    def __init__(self, failure_threshold: int = 5, recovery_timeout: int = 60):
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.failure_count = 0
        self.last_failure_time = None
        self.state = "closed"  # closed, open, half-open
    
    def can_execute(self) -> bool:
        """Check if operation can be executed"""
        if self.state == "closed":
            return True
        elif self.state == "open":
            if time.time() - self.last_failure_time > self.recovery_timeout:
                self.state = "half-open"
                return True
            return False
        else:  # half-open
            return True
    
    def record_success(self):
        """Record successful operation"""
        self.failure_count = 0
        self.state = "closed"
    
    def record_failure(self):
        """Record failed operation"""
        self.failure_count += 1
        self.last_failure_time = time.time()
        
        if self.failure_count >= self.failure_threshold:
            self.state = "open"

def with_retry(config: RetryConfig):
    """Decorator for adding retry logic to functions"""
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            last_exception = None
            
            for attempt in range(config.max_attempts):
                try:
                    return await func(*args, **kwargs)
                except Exception as e:
                    last_exception = e
                    
                    if attempt == config.max_attempts - 1:
                        raise
                    
                    delay = min(
                        config.base_delay * (config.exponential_base ** attempt),
                        config.max_delay
                    )
                    
                    if config.jitter:
                        import random
                        delay *= (0.5 + random.random() * 0.5)
                    
                    logger.warning(f"Attempt {attempt + 1} failed for {func.__name__}: {e}. Retrying in {delay:.2f}s")
                    await asyncio.sleep(delay)
            
            raise last_exception
        return wrapper
    return decorator

class DatabaseManager:
    """Manages database connections and operations"""
    
    def __init__(self):
        self.pool: Optional[asyncpg.Pool] = None
        self.database_url: str = ""
        self.circuit_breaker = CircuitBreaker()
    
    async def initialize(self, database_url: str, **pool_kwargs):
        """Initialize database connection pool"""
        self.database_url = database_url
        try:
            self.pool = await asyncpg.create_pool(database_url, **pool_kwargs)
            logger.info("✅ Database connection pool initialized")
            self.circuit_breaker.record_success()
        except Exception as e:
            logger.error(f"❌ Failed to initialize database pool: {e}")
            self.circuit_breaker.record_failure()
            raise DatabaseError(f"Database initialization failed: {e}")
    
    async def get_connection(self):
        """Get a database connection with circuit breaker protection"""
        if not self.circuit_breaker.can_execute():
            raise DatabaseError("Database circuit breaker is open")
        
        if not self.pool:
            raise DatabaseError("Database pool not initialized")
        
        try:
            conn = await self.pool.acquire()
            self.circuit_breaker.record_success()
            return conn
        except Exception as e:
            self.circuit_breaker.record_failure()
            raise DatabaseError(f"Failed to acquire database connection: {e}")
    
    async def execute_query(self, query: str, *args, **kwargs):
        """Execute a query with automatic connection management"""
        conn = await self.get_connection()
        try:
            return await conn.execute(query, *args, **kwargs)
        finally:
            await self.pool.release(conn)
    
    async def fetch_query(self, query: str, *args, **kwargs):
        """Fetch query results with automatic connection management"""
        conn = await self.get_connection()
        try:
            return await conn.fetch(query, *args, **kwargs)
        finally:
            await self.pool.release(conn)
    
    async def close(self):
        """Close database pool"""
        if self.pool:
            await self.pool.close()
            logger.info("✅ Database pool closed")

class APIManager:
    """Manages HTTP API calls with retry and circuit breaker logic"""
    
    def __init__(self):
        self.circuit_breakers: Dict[str, CircuitBreaker] = {}
        self.session: Optional[aiohttp.ClientSession] = None
    
    def get_circuit_breaker(self, service: str) -> CircuitBreaker:
        """Get or create circuit breaker for a service"""
        if service not in self.circuit_breakers:
            self.circuit_breakers[service] = CircuitBreaker()
        return self.circuit_breakers[service]
    
    async def make_request(self, method: str, url: str, service: str = "default", **kwargs):
        """Make HTTP request with circuit breaker protection"""
        circuit_breaker = self.get_circuit_breaker(service)
        
        if not circuit_breaker.can_execute():
            raise APIError(f"Circuit breaker open for service: {service}")
        
        if not self.session:
            self.session = aiohttp.ClientSession()
        
        try:
            async with self.session.request(method, url, **kwargs) as response:
                response.raise_for_status()
                result = await response.json()
                circuit_breaker.record_success()
                return result
        except Exception as e:
            circuit_breaker.record_failure()
            raise APIError(f"API request failed for {service}: {e}")

class ErrorHandler:
    """Centralized error handling system"""
    
    def __init__(self):
        self.error_counts: Dict[str, int] = {}
        self.error_history: List[Dict[str, Any]] = []
    
    def handle_error(self, error: Exception, context: str, severity: ErrorSeverity = ErrorSeverity.MEDIUM):
        """Handle and log errors with context"""
        error_type = type(error).__name__
        error_key = f"{context}:{error_type}"
        
        self.error_counts[error_key] = self.error_counts.get(error_key, 0) + 1
        
        error_record = {
            "error_type": error_type,
            "message": str(error),
            "context": context,
            "severity": severity.value,
            "count": self.error_counts[error_key],
            "timestamp": time.time(),
            "traceback": traceback.format_exc()
        }
        
        self.error_history.append(error_record)
        
        # Keep only last 1000 errors
        if len(self.error_history) > 1000:
            self.error_history = self.error_history[-1000:]
        
        # Log based on severity
        if severity == ErrorSeverity.CRITICAL:
            logger.critical(f"CRITICAL ERROR in {context}: {error}")
        elif severity == ErrorSeverity.HIGH:
            logger.error(f"HIGH SEVERITY ERROR in {context}: {error}")
        elif severity == ErrorSeverity.MEDIUM:
            logger.warning(f"ERROR in {context}: {error}")
        else:
            logger.info(f"Low severity error in {context}: {error}")
    
    def get_error_summary(self) -> Dict[str, Any]:
        """Get summary of recent errors"""
        recent_errors = [e for e in self.error_history if time.time() - e["timestamp"] < 3600]  # Last hour
        
        error_types = {}
        for error in recent_errors:
            error_type = error["error_type"]
            error_types[error_type] = error_types.get(error_type, 0) + 1
        
        return {
            "total_errors_last_hour": len(recent_errors),
            "error_types": error_types,
            "most_common_errors": sorted(
                self.error_counts.items(), 
                key=lambda x: x[1], 
                reverse=True
            )[:10]
        }

# Global instances
db_manager = DatabaseManager()
api_manager = APIManager()
error_handler = ErrorHandler()
