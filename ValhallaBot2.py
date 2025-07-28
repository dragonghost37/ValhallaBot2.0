#!/usr/bin/env python3
import sys
import time
import json
import logging
import asyncio
import discord
from discord.ext import commands, tasks
import aiohttp
from aiohttp import web

from datetime import datetime, timezone, timedelta
from discord import app_commands, Embed
import traceback
import signal
import os
from discord import Embed
from twitchio.ext import commands as twitch_commands
from collections import defaultdict, deque
import ssl
from typing import Dict, Any, Optional, List
import uuid

# Load environment variables from .env file
from dotenv import load_dotenv
load_dotenv()

# Import our production modules
from config import config
from validators import InputValidator, ValidationError, SQLSanitizer
from monitoring import monitoring, MetricsCollector
from error_handling import (
    error_handler, db_manager, api_manager, with_retry, 
    DatabaseError, APIError, RetryConfig, CircuitBreaker, ErrorSeverity
)
from security import (
    SecurityMiddleware, WebhookSecurity, create_security_config,
    security_auditor, SSLContextManager
)

# Enhanced logging configuration
logging.basicConfig(
    level=getattr(logging, config.monitoring.log_level),
    format='%(asctime)s - %(name)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s',
    handlers=[
        logging.FileHandler('valhallabot.log', encoding='utf-8'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# Suppress noisy third-party loggers in production
if config.environment == "production":
    logging.getLogger('discord').setLevel(logging.WARNING)
    logging.getLogger('aiohttp').setLevel(logging.WARNING)
    logging.getLogger('asyncpg').setLevel(logging.WARNING)

logger.info(f"🛡️ ValhallaBot2.py starting up in {config.environment} mode...")

# ---- PRODUCTION CONFIGURATION ---- #
# Configuration is now handled by the config module with environment validation
# No hardcoded secrets or fallback values allowed in production

# Initialize security configuration
security_config = create_security_config()
security_middleware = SecurityMiddleware(security_config)
webhook_security = WebhookSecurity(security_config.webhook_secret)

# Initialize database manager with production settings
db_manager.database_url = config.database.url

# Validate configuration on startup
try:
    config._validate_environment()
    logger.info("✅ Production configuration validated successfully")
except Exception as e:
    logger.critical(f"❌ Configuration validation failed: {e}")
    sys.exit(1)

rank_points = {
    "Thrall": 1,
    "Raider": 2,
    "Berserker": 3,
    "Jarl": 4,
    "Chieftain": 5,
    "Allfather": 6
}

rank_colors = {
    "Thrall": 0xA9A9A9,      # Dark Gray
    "Raider": 0x8B4513,      # Saddle Brown
    "Berserker": 0xFF4500,   # Orange Red
    "Jarl": 0x1E90FF,        # Dodger Blue
    "Chieftain": 0xFFD700,   # Gold
    "Allfather": 0x800080    # Purple
}

rank_icons = {
    "Thrall": "🪓",
    "Raider": "🛶",
    "Berserker": "🐺",
    "Jarl": "🦅",
    "Chieftain": "🛡️",
    "Allfather": "🦾"
}

intents = discord.Intents.default()
intents.message_content = True
intents.guilds = True
intents.members = True

bot = commands.Bot(command_prefix="!", intents=intents)
routes = web.RouteTableDef()

# Global variables
pool = None
twitch_bot_instance = None
web_app = None
web_runner = None
twitch_token = None
currently_live = set()
stream_chat_counts = {}
twitch_to_discord = {}
stream_raids = {}
stream_raids_sent = {}
last_live_set = set()

# Rate limiting for commands
user_command_times = defaultdict(lambda: deque(maxlen=10))

# ---- RATE LIMITING ---- #
async def check_rate_limit(user_id: int, max_commands: int = 5, window: int = 60) -> bool:
    """Simple rate limiting for commands"""
    now = time.time()
    user_times = user_command_times[user_id]
    
    # Remove old timestamps
    while user_times and user_times[0] < now - window:
        user_times.popleft()
    
    if len(user_times) >= max_commands:
        return False
    
    user_times.append(now)
    return True

# ---- PRODUCTION DATABASE INITIALIZATION ---- #
@with_retry(RetryConfig(max_attempts=3, base_delay=2.0))
async def initialize_database():
    """Create database tables with production-grade schema and security"""
    logger.info("🗄️ Initializing production database schema...")
    
    try:
        # Use the production database manager
        conn = await db_manager.get_connection()
        try:
            # Step 1: Create users table with basic schema
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    discord_id TEXT PRIMARY KEY,
                    twitch_username TEXT UNIQUE,
                    rank TEXT DEFAULT 'Thrall',
                    points INTEGER DEFAULT 0,
                    created_at TIMESTAMP DEFAULT NOW(),
                    updated_at TIMESTAMP DEFAULT NOW(),
                    last_activity TIMESTAMP DEFAULT NOW(),
                    metadata JSONB DEFAULT '{}'
                )
            """)
            
            # Step 2: Add missing columns if they don't exist
            await conn.execute("""
                DO $$ 
                BEGIN 
                    -- Add is_active column if missing
                    IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                                  WHERE table_name = 'users' AND column_name = 'is_active') THEN
                        ALTER TABLE users ADD COLUMN is_active BOOLEAN DEFAULT TRUE;
                    END IF;
                    
                    -- Add constraints if table already exists
                    BEGIN
                        ALTER TABLE users ADD CONSTRAINT check_discord_id CHECK (discord_id ~ '^[0-9]{17,19}$');
                    EXCEPTION
                        WHEN duplicate_object THEN NULL;
                    END;
                    
                    BEGIN
                        ALTER TABLE users ADD CONSTRAINT check_twitch_username CHECK (twitch_username ~ '^[a-zA-Z0-9_]{4,25}$');
                    EXCEPTION
                        WHEN duplicate_object THEN NULL;
                    END;
                    
                    BEGIN
                        ALTER TABLE users ADD CONSTRAINT check_rank CHECK (rank IN ('Thrall', 'Raider', 'Berserker', 'Jarl', 'Chieftain', 'Allfather'));
                    EXCEPTION
                        WHEN duplicate_object THEN NULL;
                    END;
                    
                    BEGIN
                        ALTER TABLE users ADD CONSTRAINT check_points CHECK (points >= 0);
                    EXCEPTION
                        WHEN duplicate_object THEN NULL;
                    END;
                END $$
            """)
            
            # Step 3: Create other tables
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS raids (
                    id SERIAL PRIMARY KEY,
                    raider_id TEXT NOT NULL,
                    target_id TEXT NOT NULL,
                    viewers INTEGER DEFAULT 0,
                    points_awarded INTEGER DEFAULT 0,
                    timestamp TIMESTAMP DEFAULT NOW(),
                    raid_data JSONB DEFAULT '{}',
                    processed BOOLEAN DEFAULT FALSE
                )
            """)
            
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS chat_points (
                    id SERIAL PRIMARY KEY,
                    chatter_id TEXT NOT NULL,
                    streamer_id TEXT NOT NULL,
                    points_awarded INTEGER DEFAULT 0,
                    timestamp TIMESTAMP DEFAULT NOW(),
                    session_id UUID DEFAULT gen_random_uuid()
                )
            """)
            
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS chats (
                    chatter_id TEXT NOT NULL,
                    streamer_id TEXT NOT NULL,
                    count INTEGER DEFAULT 0,
                    last_chat TIMESTAMP DEFAULT NOW(),
                    PRIMARY KEY (chatter_id, streamer_id)
                )
            """)
            
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS referrals (
                    id SERIAL PRIMARY KEY,
                    referrer_id TEXT NOT NULL,
                    referred_id TEXT NOT NULL,
                    awarded BOOLEAN DEFAULT FALSE,
                    points_awarded INTEGER DEFAULT 0,
                    created_at TIMESTAMP DEFAULT NOW(),
                    awarded_at TIMESTAMP,
                    UNIQUE(referrer_id, referred_id)
                )
            """)
            
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS audit_log (
                    id SERIAL PRIMARY KEY,
                    user_id TEXT,
                    action TEXT NOT NULL,
                    details JSONB DEFAULT '{}',
                    ip_address INET,
                    user_agent TEXT,
                    timestamp TIMESTAMP DEFAULT NOW()
                )
            """)
            
            # Step 4: Create indexes safely
            indexes = [
                "CREATE INDEX IF NOT EXISTS idx_users_twitch ON users(twitch_username) WHERE twitch_username IS NOT NULL",
                "CREATE INDEX IF NOT EXISTS idx_users_created_at ON users(created_at)",
                "CREATE INDEX IF NOT EXISTS idx_users_last_activity ON users(last_activity)",
                "CREATE INDEX IF NOT EXISTS idx_raids_timestamp_desc ON raids(timestamp DESC)",
                "CREATE INDEX IF NOT EXISTS idx_chat_points_timestamp ON chat_points(timestamp DESC)",
                "CREATE INDEX IF NOT EXISTS idx_audit_log_timestamp ON audit_log(timestamp DESC)"
            ]
            
            for index_sql in indexes:
                try:
                    await conn.execute(index_sql)
                except Exception as idx_error:
                    logger.warning(f"Index creation failed (non-critical): {idx_error}")
            
            # Step 5: Create points index with is_active check
            try:
                await conn.execute("""
                    DO $$ 
                    BEGIN 
                        IF EXISTS (SELECT 1 FROM information_schema.columns 
                                  WHERE table_name = 'users' AND column_name = 'is_active') THEN
                            CREATE INDEX IF NOT EXISTS idx_users_points_desc ON users(points DESC) WHERE is_active = TRUE;
                        ELSE
                            CREATE INDEX IF NOT EXISTS idx_users_points_desc ON users(points DESC);
                        END IF;
                    END $$
                """)
            except Exception as idx_error:
                logger.warning(f"Points index creation failed (non-critical): {idx_error}")
            
            # Step 6: Create trigger function
            await conn.execute("""
                CREATE OR REPLACE FUNCTION update_updated_at_column()
                RETURNS TRIGGER AS $$
                BEGIN
                    NEW.updated_at = NOW();
                    RETURN NEW;
                END;
                $$ language 'plpgsql'
            """)
            
            # Step 7: Create trigger
            await conn.execute("""
                DROP TRIGGER IF EXISTS update_users_updated_at ON users;
                CREATE TRIGGER update_users_updated_at
                    BEFORE UPDATE ON users
                    FOR EACH ROW
                    EXECUTE FUNCTION update_updated_at_column()
            """)
            
            # Step 8: Verify critical tables exist
            tables_to_verify = ['users', 'raids', 'chat_points', 'chats', 'referrals', 'audit_log']
            for table in tables_to_verify:
                result = await conn.fetchval(
                    "SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name = $1)",
                    table
                )
                if not result:
                    raise DatabaseError(f"Failed to create table: {table}")
            
            # Step 9: Log audit event
            await conn.execute(
                "INSERT INTO audit_log (action, details) VALUES ($1, $2)",
                "database_initialized",
                json.dumps({"environment": config.environment, "timestamp": datetime.utcnow().isoformat()})
            )
            
            logger.info("✅ Production database schema initialized successfully")
            monitoring.metrics.increment_counter("database_operations_total", labels={"operation": "initialize", "status": "success"})
            
        finally:
            await db_manager.pool.release(conn)
            
    except Exception as e:
        logger.error(f"❌ Database initialization failed: {e}")
        monitoring.metrics.increment_counter("database_operations_total", labels={"operation": "initialize", "status": "error"})
        error_handler.handle_error(e, "database_initialization", severity=ErrorSeverity.CRITICAL)
        raise DatabaseError(f"Database initialization failed: {e}")

# ---- PRODUCTION TWITCH INTEGRATION ---- #
@with_retry(RetryConfig(max_attempts=3, base_delay=1.0))
async def get_all_twitch_users() -> dict:
    """Get all linked Twitch usernames and their Discord IDs from database with validation"""
    request_id = str(uuid.uuid4())
    monitoring.performance_monitor.start_request(request_id, "get_all_twitch_users")
    try:
        conn = await db_manager.get_connection()
        try:
            rows = await conn.fetch(
                "SELECT twitch_username, discord_id FROM users WHERE twitch_username IS NOT NULL AND is_active = TRUE"
            )
            user_map = {}
            for row in rows:
                try:
                    username = InputValidator.validate_twitch_username(row['twitch_username'])
                    discord_id = InputValidator.validate_discord_id(row['discord_id'])
                    user_map[username] = discord_id
                except ValidationError as e:
                    logger.warning(f"Invalid user in get_all_twitch_users: {e}")
            monitoring.metrics.set_gauge("active_twitch_users", len(user_map))
            monitoring.performance_monitor.end_request(request_id, True)
            return user_map
        finally:
            await db_manager.pool.release(conn)
    except Exception as e:
        logger.error(f"Failed to get Twitch users: {e}")
        error_handler.handle_error(e, "get_all_twitch_users")
        monitoring.performance_monitor.end_request(request_id, False)
        return {}

@with_retry(RetryConfig(max_attempts=3, base_delay=2.0))
async def get_twitch_oauth_token() -> Optional[str]:
    """Get Twitch OAuth token with secure handling and retry logic"""
    url = "https://id.twitch.tv/oauth2/token"
    
    # Validate configuration
    if not config.twitch.client_id or not config.twitch.client_secret:
        raise APIError("Twitch credentials not configured")
    
    data = {
        'client_id': config.twitch.client_id,
        'client_secret': config.twitch.client_secret,
        'grant_type': 'client_credentials'
    }
    
    try:
        response_data = await api_manager.make_request(
            'POST', 
            url, 
            service="twitch_auth",
            data=data,
            timeout=config.twitch.api_timeout
        )
        
        if 'access_token' not in response_data:
            raise APIError("Invalid token response from Twitch")
        
        token = response_data['access_token']
        
        # Log successful authentication (without exposing token)
        logger.info("✅ Twitch OAuth token obtained successfully")
        monitoring.metrics.increment_counter("twitch_auth_requests", labels={"status": "success"})
        
        return token
        
    except Exception as e:
        logger.error(f"Failed to get Twitch OAuth token: {e}")
        monitoring.metrics.increment_counter("twitch_auth_requests", labels={"status": "error"})
        error_handler.handle_error(e, "twitch_oauth")
        raise APIError(f"Twitch authentication failed: {e}")

@with_retry(RetryConfig(max_attempts=3, base_delay=1.0))
async def get_twitch_user_id(username: str, twitch_token: str) -> Optional[str]:
    """Get Twitch user ID with validation and secure handling"""
    # Validate inputs
    try:
        validated_username = InputValidator.validate_twitch_username(username)
    except ValidationError as e:
        logger.error(f"Invalid Twitch username: {username} - {e}")
        return None
    
    if not twitch_token:
        raise APIError("Twitch token is required")
    
    url = f"https://api.twitch.tv/helix/users?login={validated_username}"
    headers = {
        "Client-ID": config.twitch.client_id,
        "Authorization": f"Bearer {twitch_token}"
    }
    
    try:
        response_data = await api_manager.make_request(
            'GET',
            url,
            service="twitch_api",
            headers=headers,
            timeout=config.twitch.api_timeout
        )
        
        if not response_data.get('data'):
            logger.warning(f"⚠️ User {validated_username} not found on Twitch")
            monitoring.metrics.increment_counter("twitch_user_lookups", labels={"status": "not_found"})
            return None
        
        user_id = response_data['data'][0]['id']
        
        # Validate user ID format
        if not user_id or not user_id.isdigit():
            raise APIError(f"Invalid user ID received: {user_id}")
        
        logger.info(f"✅ Got Twitch user ID for {validated_username}: {user_id}")
        monitoring.metrics.increment_counter("twitch_user_lookups", labels={"status": "success"})
        return user_id
        
    except Exception as e:
        logger.error(f"❌ Failed to get user ID for {validated_username}: {e}")
        monitoring.metrics.increment_counter("twitch_user_lookups", labels={"status": "error"})
        error_handler.handle_error(e, f"twitch_user_lookup_{validated_username}")
        return None

@with_retry(RetryConfig(max_attempts=3, base_delay=2.0))
async def subscribe_to_raid_events(user_id: str, twitch_token: str) -> bool:
    """Subscribe to raid events with validation and secure handling"""
    # Validate inputs
    if not user_id or not user_id.isdigit():
        raise ValidationError(f"Invalid user ID: {user_id}")
    
    if not twitch_token:
        raise APIError("Twitch token is required")
    
    url = "https://api.twitch.tv/helix/eventsub/subscriptions"
    headers = {
        "Client-ID": config.twitch.client_id,
        "Authorization": f"Bearer {twitch_token}",
        "Content-Type": "application/json"
    }
    
    data = {
        "type": "channel.raid",
        "version": "1",
        "condition": {
            "to_broadcaster_user_id": user_id
        },
        "transport": {
            "method": "webhook",
            "callback": config.webhook.url + "/eventsub",
            "secret": config.twitch.eventsub_secret
        }
    }
    
    try:
        response_data = await api_manager.make_request(
            'POST',
            url,
            service="twitch_eventsub",
            headers=headers,
            json=data,
            timeout=config.twitch.api_timeout
        )
        
        logger.info(f"✅ Subscribed to raid events for user {user_id}")
        monitoring.metrics.increment_counter("twitch_subscriptions", labels={"type": "raid", "status": "success"})
        return True
        
    except Exception as e:
        logger.error(f"❌ Failed to subscribe to raid events for user {user_id}: {e}")
        monitoring.metrics.increment_counter("twitch_subscriptions", labels={"type": "raid", "status": "error"})
        error_handler.handle_error(e, f"eventsub_subscription_{user_id}")
        return False     

# ---- PRODUCTION EVENTSUB HANDLER ---- #
@routes.post("/eventsub")
async def handle_eventsub(request: web.Request) -> web.Response:
    """Handle Twitch EventSub webhooks with security validation"""
    request_id = str(uuid.uuid4())
    client_ip = request.headers.get('X-Forwarded-For', request.remote)
    
    monitoring.performance_monitor.start_request(request_id, "handle_eventsub")
    
    try:
        # Validate payload size
        if request.content_length and request.content_length > config.webhook.max_payload_size:
            logger.warning(f"EventSub payload too large: {request.content_length} bytes from {client_ip}")
            security_auditor.log_security_event("payload_too_large", client_ip, {"size": request.content_length})
            monitoring.performance_monitor.end_request(request_id, False)
            raise web.HTTPRequestEntityTooLarge()
        
        # Get raw payload for signature validation
        raw_payload = await request.read()
        
        # Validate webhook signature
        signature = request.headers.get('Twitch-Eventsub-Message-Signature')
        if not webhook_security.verify_signature(raw_payload, signature):
            logger.warning(f"Invalid EventSub signature from {client_ip}")
            security_auditor.log_security_event("invalid_signature", client_ip, {"endpoint": "/eventsub"})
            monitoring.metrics.increment_counter("webhook_requests", labels={"status": "invalid_signature"})
            monitoring.performance_monitor.end_request(request_id, False)
            raise web.HTTPForbidden(text="Invalid signature")
        
        # Parse JSON payload
        try:
            payload = json.loads(raw_payload.decode('utf-8'))
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            logger.error(f"Invalid JSON payload from {client_ip}: {e}")
            monitoring.metrics.increment_counter("webhook_requests", labels={"status": "invalid_json"})
            monitoring.performance_monitor.end_request(request_id, False)
            raise web.HTTPBadRequest(text="Invalid JSON")
        
        # Handle challenge verification
        if "challenge" in payload:
            challenge = payload["challenge"]
            logger.info(f"EventSub challenge received from {client_ip}")
            monitoring.metrics.increment_counter("webhook_requests", labels={"status": "challenge"})
            monitoring.performance_monitor.end_request(request_id, True)
            return web.Response(text=challenge, content_type="text/plain")
        
        # Process raid events
        if payload.get("subscription", {}).get("type") == "channel.raid":
            await process_raid_event(payload, client_ip, request_id)
        else:
            logger.info(f"Unhandled EventSub type: {payload.get('subscription', {}).get('type')}")
        
        monitoring.metrics.increment_counter("webhook_requests", labels={"status": "success"})
        monitoring.performance_monitor.end_request(request_id, True)
        return web.Response(status=200)
        
    except web.HTTPException:
        raise
    except Exception as e:
        logger.error(f"EventSub handler error: {e}")
        error_handler.handle_error(e, "eventsub_handler")
        monitoring.metrics.increment_counter("webhook_requests", labels={"status": "error"})
        monitoring.performance_monitor.end_request(request_id, False)
        raise web.HTTPInternalServerError()

async def process_raid_event(payload: dict, client_ip: str, request_id: str):
    """Process raid event with validation and secure database operations"""
    try:
        event = payload["event"]
        
        # Validate and sanitize event data
        raider = InputValidator.validate_twitch_username(event["from_broadcaster_user_login"])
        target = InputValidator.validate_twitch_username(event["to_broadcaster_user_login"])
        viewers = InputValidator.validate_points(event["viewers"])
        
        logger.info(f"Processing raid: {raider} -> {target} ({viewers} viewers)")
        
        # Database operations with connection management
        conn = await db_manager.get_connection()
        try:
            # Get user data with validation
            raider_row = await conn.fetchrow(
                "SELECT discord_id, points, rank FROM users WHERE twitch_username = $1 AND is_active = TRUE",
                raider
            )
            target_row = await conn.fetchrow(
                "SELECT discord_id, points, rank FROM users WHERE twitch_username = $1 AND is_active = TRUE",
                target
            )
            
            points_awarded = 0
            raid_count = 0
            
            if raider_row and target_row:
                raider_id = InputValidator.validate_discord_id(raider_row["discord_id"])
                target_id = InputValidator.validate_discord_id(target_row["discord_id"])
                
                # Check raid frequency (prevent abuse)
                raid_count = await conn.fetchval(
                    "SELECT COUNT(*) FROM raids WHERE raider_id = $1 AND target_id = $2 AND timestamp > NOW() - INTERVAL '30 days'",
                    raider_id, target_id
                )
                
                if raid_count >= 5:
                    logger.info(f"Raid limit reached for {raider} -> {target} (count: {raid_count})")
                    points_awarded = 0
                else:
                    # Calculate points with validation
                    points_awarded = min(viewers * 10, 10000)  # Cap at 10k points
                    
                    # Update raider points
                    await conn.execute(
                        "UPDATE users SET points = points + $1, last_activity = NOW() WHERE discord_id = $2",
                        points_awarded, raider_id
                    )
                    
                    # Update rank
                    await update_user_rank(conn, raider_id)
                    
                    # Record raid
                    await conn.execute(
                        "INSERT INTO raids (raider_id, target_id, viewers, points_awarded, raid_data) VALUES ($1, $2, $3, $4, $5)",
                        raider_id, target_id, viewers, points_awarded, json.dumps({
                            "raider_username": raider,
                            "target_username": target,
                            "client_ip": client_ip,
                            "request_id": request_id
                        })
                    )
                    
                    logger.info(f"✅ Raid processed: {raider} earned {points_awarded} points")
                
                # Log audit event
                await conn.execute(
                    "INSERT INTO audit_log (user_id, action, details, ip_address) VALUES ($1, $2, $3, $4)",
                    raider_id, "raid_processed", json.dumps({
                        "target": target,
                        "viewers": viewers,
                        "points_awarded": points_awarded,
                        "raid_count": raid_count
                    }), client_ip
                )
                
            elif raider_row and not target_row:
                logger.info(f"Target {target} not found in database for raid from {raider}")
            elif not raider_row:
                logger.info(f"Raider {raider} not found in database")
            
            # Update metrics
            monitoring.metrics.increment_counter("raids_processed", labels={
                "raider_found": str(bool(raider_row)),
                "target_found": str(bool(target_row)),
                "points_awarded": str(points_awarded > 0)
            })
            monitoring.metrics.record_histogram("raid_viewers", viewers)
            monitoring.metrics.record_histogram("raid_points_awarded", points_awarded)
            
        finally:
            await db_manager.pool.release(conn)
            
    except ValidationError as e:
        logger.warning(f"Invalid raid event data: {e}")
        monitoring.metrics.increment_counter("raid_validation_errors")
    except Exception as e:
        logger.error(f"Error processing raid event: {e}")
        error_handler.handle_error(e, "process_raid_event")
        raise

# ---- PRODUCTION HEALTH CHECK ENDPOINTS ---- #
@routes.get("/health")
async def health_check(request: web.Request) -> web.Response:
    """Basic health check endpoint"""
    try:
        # Quick health check
        health_status = await monitoring.health_checker.run_checks()
        overall_health = monitoring.health_checker.get_overall_health()
        
        status_code = 200 if overall_health["status"] == "healthy" else 503
        
        return web.json_response({
            "status": overall_health["status"],
            "timestamp": datetime.utcnow().isoformat(),
            "version": "2.0.0-production",
            "environment": config.environment,
            "checks": overall_health["checks"]
        }, status=status_code)
        
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return web.json_response({
            "status": "error",
            "timestamp": datetime.utcnow().isoformat(),
            "error": str(e)
        }, status=503)

@routes.get("/health/live")
async def liveness_probe(request: web.Request) -> web.Response:
    """Kubernetes liveness probe endpoint"""
    try:
        # Basic liveness check - just verify the service is responding
        return web.json_response({
            "status": "alive",
            "timestamp": datetime.utcnow().isoformat(),
            "uptime_seconds": time.time() - monitoring.metrics.start_time
        })
    except Exception as e:
        logger.error(f"Liveness probe failed: {e}")
        return web.json_response({
            "status": "dead",
            "error": str(e)
        }, status=503)

@routes.get("/health/ready")
async def readiness_probe(request: web.Request) -> web.Response:
    """Kubernetes readiness probe endpoint"""
    try:
        # Check if service is ready to handle requests
        checks = {
            "database": await check_database_ready(),
            "discord": check_discord_ready(),
            "twitch": await check_twitch_ready()
        }
        
        all_ready = all(checks.values())
        status_code = 200 if all_ready else 503
        
        return web.json_response({
            "status": "ready" if all_ready else "not_ready",
            "timestamp": datetime.utcnow().isoformat(),
            "checks": checks
        }, status=status_code)
        
    except Exception as e:
        logger.error(f"Readiness probe failed: {e}")
        return web.json_response({
            "status": "not_ready",
            "error": str(e)
        }, status=503)

@routes.get("/status")
async def status_endpoint(request: web.Request) -> web.Response:
    """Comprehensive status endpoint for monitoring"""
    try:
        status_report = monitoring.get_status_report()
        security_summary = security_auditor.get_security_summary()
        error_summary = error_handler.get_error_summary()
        
        return web.json_response({
            "service": "ValhallaBot",
            "version": "2.0.0-production",
            "environment": config.environment,
            "status": status_report,
            "security": security_summary,
            "errors": error_summary
        })
        
    except Exception as e:
        logger.error(f"Status endpoint failed: {e}")
        return web.json_response({
            "error": str(e)
        }, status=500)

# Health check helper functions
async def check_database_ready() -> bool:
    """Check if database is ready"""
    try:
        conn = await db_manager.get_connection()
        try:
            await conn.fetchval("SELECT 1")
            return True
        finally:
            await db_manager.pool.release(conn)
    except Exception:
        return False

def check_discord_ready() -> bool:
    """Check if Discord bot is ready"""
    return bot.is_ready() if 'bot' in globals() else False

async def check_twitch_ready() -> bool:
    """Check if Twitch integration is ready"""
    try:
        # Simple check - try to get OAuth token
        token = await get_twitch_oauth_token()
        return bool(token)
    except Exception:
        return False

# ---- AWARD & RANK FUNCTIONS ---- #
async def award_chat_points(conn, chatter_discord_id, streamer_twitch_username, count=1):
    streamer_row = await conn.fetchrow("SELECT discord_id, rank FROM users WHERE twitch_username = $1", streamer_twitch_username)
    if not streamer_row:
        return
    streamer_id = streamer_row["discord_id"]
    rank = streamer_row["rank"]
    points_per_message = rank_points.get(rank, 1)
    total_points = points_per_message * count

    # Calculate points awarded in last 48 hours
    recent_points = await conn.fetchval("""
        SELECT COALESCE(SUM(points_awarded), 0)
        FROM chat_points
        WHERE chatter_id = $1 AND streamer_id = $2 AND timestamp > NOW() - INTERVAL '48 hours'
    """, chatter_discord_id, streamer_id)

    if recent_points >= 100:
        return  # Already maxed out for this streamer in this window

    points_to_award = min(total_points, 100 - recent_points)
    if points_to_award <= 0:
        return

    await conn.execute("UPDATE users SET points = points + $1 WHERE discord_id = $2", points_to_award, chatter_discord_id)
    await update_user_rank(conn, chatter_discord_id)
    await conn.execute("""
        INSERT INTO chat_points (chatter_id, streamer_id, points_awarded, timestamp)
        VALUES ($1, $2, $3, NOW())
    """, chatter_discord_id, streamer_id, points_to_award)

async def update_user_rank(conn, discord_id):
    # Get all users sorted by points descending
    users = await conn.fetch("SELECT discord_id, points FROM users ORDER BY points DESC")
    total_users = len(users)
    if total_users == 0:
        return

    # Find this user's index in the sorted list (0-based)
    user_index = next((i for i, u in enumerate(users) if u["discord_id"] == str(discord_id)), None)
    if user_index is None:
        return
    percentile = user_index / total_users

    row = await conn.fetchrow("SELECT rank FROM users WHERE discord_id = $1", str(discord_id))
    old_rank = row["rank"] if row else "Thrall"

    if percentile < 0.05:
        new_rank = "Allfather"
    elif percentile < 0.15:
        new_rank = "Chieftain"
    elif percentile < 0.30:
        new_rank = "Jarl"
    elif percentile < 0.50:
        new_rank = "Berserker"
    elif percentile < 0.80:
        new_rank = "Raider"
    else:
        new_rank = "Thrall"

    if new_rank != old_rank:
        await conn.execute("UPDATE users SET rank = $1 WHERE discord_id = $2", new_rank, discord_id)
        # Notify in bot-commands
        channel = discord.utils.get(bot.get_all_channels(), name="╡bot-commands")
        if channel:
            rank_order = ["Thrall", "Raider", "Berserker", "Jarl", "Chieftain", "Allfather"]
            if rank_order.index(new_rank) > rank_order.index(old_rank):
                action = "promoted to"
            else:
                action = "demoted to"
            await channel.send(
                f"🎉 <@{discord_id}> has been **{action} {new_rank}**!"
            )

    # Assign Discord role
    member = None
    for guild in bot.guilds:
        member = guild.get_member(int(discord_id))
        if not member:
            try:
                member = await guild.fetch_member(int(discord_id))
            except Exception:
                continue
        if member:
            break
    if member:
        role_names = ["Thrall", "Raider", "Berserker", "Jarl", "Chieftain", "Allfather"]
        roles = {r.name: r for r in member.guild.roles if r.name in role_names}
        current_roles = [r for r in member.roles if r.name in role_names]
        for r in current_roles:
            try:
                await member.remove_roles(r)
            except Exception as e:
                logger.exception(f"Error removing role {r.name} from {member.display_name}:")
        new_role = roles.get(new_rank)
        if new_role:
            try:
                await member.add_roles(new_role)
            except Exception:
                pass

    # Check for referral reward
    points_row = await conn.fetchrow("SELECT points FROM users WHERE discord_id = $1", discord_id)
    if points_row and points_row["points"] >= 300:
        # Find referrer who hasn't been awarded yet
        referral = await conn.fetchrow(
            "SELECT referrer_id FROM referrals WHERE referred_id = $1 AND awarded = FALSE",
            discord_id
        )
        if referral:
            referrer_id = referral["referrer_id"]
            await conn.execute("UPDATE users SET points = points + 200 WHERE discord_id = $1", referrer_id)
            await conn.execute("UPDATE referrals SET awarded = TRUE WHERE referrer_id = $1 AND referred_id = $2", referrer_id, discord_id)
            # Notify the referrer
            channel = discord.utils.get(bot.get_all_channels(), name="╡bot-commands")
            if channel:
                await channel.send(f"🎉 <@{referrer_id}> has been awarded 200 points for referring <@{discord_id}> (who reached 300 points)!")

async def log_chat(chatter_discord_id, streamer_discord_id):
    async with pool.acquire() as conn:
        await conn.execute("""
            INSERT INTO chats (chatter_id, streamer_id, count)
            VALUES ($1, $2, 1)
            ON CONFLICT (chatter_id, streamer_id) DO UPDATE SET count = chats.count + 1
        """, chatter_discord_id, streamer_discord_id)

# ---- TWITCH BOT INTEGRATION ---- #
from twitchio.ext import commands as twitch_commands

# ---- TWITCH BOT INTEGRATION ---- #
class TwitchBot(twitch_commands.Bot):
    def __init__(self, chat_counts, user_map, channels):
        super().__init__(
            token=config.twitch.bot_token,
            prefix="!",
            initial_channels=[]
        )
        self.chat_counts = chat_counts
        self.user_map = user_map
        self.channels_to_join = channels

    async def event_ready(self):
        logger.info(f"TwitchBot connected as {self.nick}")
        try:
            await self.join_channels(self.channels_to_join)
        except Exception as e:
            logger.exception("Error joining Twitch channels:")

    async def event_message(self, message):
        if message.echo:
            return
        chatter = message.author.name.lower()
        streamer = message.channel.name.lower()
        discord_chatter = self.user_map.get(chatter)
        discord_streamer = self.user_map.get(streamer)
        # Prevent users from earning points for chatting in their own stream
        if discord_chatter and discord_streamer and discord_chatter != discord_streamer:
            if streamer not in self.chat_counts:
                self.chat_counts[streamer] = {}
            if discord_chatter not in self.chat_counts[streamer]:
                self.chat_counts[streamer][discord_chatter] = 0
            self.chat_counts[streamer][discord_chatter] += 1
            await log_chat(discord_chatter, discord_streamer)

async def log_chat(chatter_discord_id, streamer_discord_id):
    async with pool.acquire() as conn:
        await conn.execute("""
            INSERT INTO chats (chatter_id, streamer_id, count)
            VALUES ($1, $2, 1)
            ON CONFLICT (chatter_id, streamer_id) DO UPDATE SET count = chats.count + 1
        """, chatter_discord_id, streamer_discord_id)

# ---- BACKGROUND TASKS ---- #
@tasks.loop(minutes=1)
async def check_live_streams():
    global currently_live
    global twitch_token
    await bot.wait_until_ready()

    if not twitch_token:
        await get_twitch_oauth_token()

    live_now = set()
    stream_info = {}

    async with pool.acquire() as conn:
        users = await conn.fetch("SELECT discord_id, twitch_username FROM users WHERE twitch_username IS NOT NULL")
        for user in users:
            twitch_username = user["twitch_username"]
            twitch_to_discord[twitch_username] = user["discord_id"]

        async with aiohttp.ClientSession() as session:
            headers = {
                'Client-ID': config.twitch.client_id,
                'Authorization': f'Bearer {twitch_token}'
            }

            for user in users:
                twitch_username = user["twitch_username"]
                url = f"https://api.twitch.tv/helix/streams?user_login={twitch_username}"
                try:
                    async with session.get(url, headers=headers) as resp:
                        if resp.status == 401:  # Token expired
                            await get_twitch_oauth_token()
                            headers['Authorization'] = f'Bearer {twitch_token}'
                            async with session.get(url, headers=headers) as retry_resp:
                                data = await retry_resp.json()
                        else:
                            data = await resp.json()

                        if data.get('data'):
                            live_now.add(twitch_username)
                            stream_info[twitch_username] = data['data'][0]
                except Exception as e:
                    logger.error(f"Error checking stream status for {twitch_username}: {e}")

    # Handle newly live streams
    newly_live = live_now - currently_live
    for twitch_username in newly_live:
        discord_id = twitch_to_discord.get(twitch_username)
        stream = stream_info.get(twitch_username)
        channel = discord.utils.get(bot.get_all_channels(), name="╡now-live")

        if channel and discord_id and stream:
            user_obj = None
            for guild in bot.guilds:
                user_obj = guild.get_member(int(discord_id))
                if user_obj:
                    break
            if not user_obj:
                try:
                    user_obj = await bot.fetch_user(int(discord_id))
                except:
                    continue

            async with pool.acquire() as conn:
                row = await conn.fetchrow("SELECT rank FROM users WHERE discord_id = $1", str(discord_id))
                rank = row["rank"] if row else "Unknown"

            color = rank_colors.get(rank, 0x7289DA)
            embed = discord.Embed(
                title=f"{user_obj.display_name} is now LIVE on Twitch!",
                color=color,
                description=f"**Valhalla Gaming Rank:** {rank}\n"
                            f"🎮 **Game:** {stream.get('game_name')}\n"
                            f"📺 **Title:** {stream.get('title')}\n"
                            f"👁️ **Viewers:** {stream.get('viewer_count')}\n"
                            f"🔗 [Watch here](https://twitch.tv/{twitch_username})"
            )
            embed.timestamp = datetime.now(timezone.utc)
            await channel.send(embed=embed)

    # Handle ended streams
    ended_streams = currently_live - live_now
    for twitch_username in ended_streams:
        discord_id = twitch_to_discord.get(twitch_username)
        chatters = stream_chat_counts.get(twitch_username, {})
        total_chats = sum(chatters.values())
        channel = discord.utils.get(bot.get_all_channels(), name="╡bot-commands")
        if channel and discord_id:
            # Get streamer display name and rank
            streamer_name = twitch_username
            rank = "Unknown"
            for guild in bot.guilds:
                member = guild.get_member(int(discord_id))
                if member:
                    streamer_name = member.display_name
                    break
            
            # Fetch rank from DB
            async with pool.acquire() as conn:
                row = await conn.fetchrow("SELECT rank FROM users WHERE discord_id = $1", str(discord_id))
                if row:
                    rank = row["rank"]
            
            color = rank_colors.get(rank, 0x7289DA)

            # Handle raids sent - post points awarded messages
            raids_sent = stream_raids_sent.pop(twitch_username, [])
            for target, viewers, points in raids_sent:
                target_id = twitch_to_discord.get(target)
                streamer_mention = f"<@{discord_id}>"
                target_mention = f"<@{target_id}>" if target_id else target
                streamer_url = f"https://twitch.tv/{twitch_username}"
                target_url = f"https://twitch.tv/{target}"
                if points == 0:
                    await channel.send(
                        f"{streamer_mention}: You raided {target_mention} ({target_url}) with {viewers} viewers but were **NOT** awarded {viewers*10} points since they are not a registered streamer in this Discord. "
                        "Consider referring them here and earn 200 points once they reach 300 points!"
                    )
                else:
                    await channel.send(
                        f"{streamer_mention} ({streamer_url}) just raided {target_mention} ({target_url}) with {viewers} viewers and was awarded {points} points!"
                    )

            # Build stream summary embed
            embed = discord.Embed(
                title=f"{streamer_name}'s Stream Summary",
                color=color,
                description=f"Here's a summary of the support you received:"
            )

            # Chatters
            if chatters:
                chatter_mentions = " ".join(f"<@{chatter_id}>" for chatter_id in chatters.keys())
                embed.add_field(
                    name="Chatters",
                    value=f"You received {total_chats} chats from Valhalla Warriors\n{chatter_mentions}",
                    inline=False
                )
            else:
                embed.add_field(name="Chatters", value="No chatters this stream.", inline=False)

            # Raids Received
            raids = stream_raids.pop(twitch_username, [])
            if raids:
                total_raids = len(raids)
                total_raid_viewers = sum(r[1] for r in raids)
                raider_mentions = " ".join(
                    f"<@{twitch_to_discord.get(r[0], '')}>" if twitch_to_discord.get(r[0]) else f"{r[0]}"
                    for r in raids
                )
                embed.add_field(
                    name="Raids",
                    value=f"You received {total_raids} raid{'s' if total_raids > 1 else ''} with {total_raid_viewers} viewer{'s' if total_raid_viewers != 1 else ''}\n{raider_mentions}",
                    inline=False
                )
            else:
                embed.add_field(name="Raids", value="No raids this stream.", inline=False)

            # Raids Sent (summary only)
            if raids_sent:
                total_sent = len(raids_sent)
                total_sent_viewers = sum(r[1] for r in raids_sent)
                target_mentions = " ".join(
                    f"<@{twitch_to_discord.get(r[0], '')}>" if twitch_to_discord.get(r[0]) else f"{r[0]}"
                    for r in raids_sent
                )
                embed.add_field(
                    name="Raids Sent",
                    value=f"You sent {total_sent} raid{'s' if total_sent > 1 else ''} with {total_sent_viewers} viewer{'s' if total_sent_viewers != 1 else ''}\n{target_mentions}",
                    inline=False
                )
            embed.timestamp = datetime.now(timezone.utc)

            # Tag the streamer and send summary
            await channel.send(f"Hey <@{discord_id}>, Awesome stream!")
            await channel.send(embed=embed)

            # Award chat points based on post-stream chat counts
            async with pool.acquire() as conn:
                for chatter_id, count in chatters.items():
                    await award_chat_points(conn, chatter_id, twitch_username, count)

        stream_chat_counts.pop(twitch_username, None)
    
    currently_live.clear()
    currently_live.update(live_now)

@tasks.loop(minutes=1)
async def auto_post_currently_live():
    global last_live_set
    await bot.wait_until_ready()
    global twitch_token
    if not twitch_token:
        await get_twitch_oauth_token()
    
    async with pool.acquire() as conn:
        users = await conn.fetch("SELECT discord_id, twitch_username, rank FROM users WHERE twitch_username IS NOT NULL")
        if not users:
            return
        
        live_by_rank = {}
        stream_details = {}
        current_live_set = set()
        
        async with aiohttp.ClientSession() as session:
            headers = {'Client-ID': config.twitch.client_id, 'Authorization': f'Bearer {twitch_token}'}
            for user in users:
                discord_id = user["discord_id"]
                twitch_username = user["twitch_username"]
                rank = user["rank"]
                url = f"https://api.twitch.tv/helix/streams?user_login={twitch_username}"
                try:
                    async with session.get(url, headers=headers) as resp:
                        data = await resp.json()
                        if data.get('data'):
                            live_by_rank.setdefault(rank, []).append((discord_id, twitch_username))
                            stream_details[twitch_username] = data['data'][0]
                            current_live_set.add(twitch_username)
                except Exception as e:
                    logger.error(f"Error checking live status for {twitch_username}: {e}")
        
        if not live_by_rank:
            return

        if current_live_set != last_live_set:
            rank_order = [
                ("Allfather", "🦾", 6, "Earn 6 points/message (max 1 per minute per stream, up to 2 different streams per minute)"),
                ("Chieftain", "🛡️", 5, "Earn 5 points/message (max 1 per minute per stream, up to 2 different streams per minute)"),
                ("Jarl", "🦅", 4, "Earn 4 points/message (max 1 per minute per stream, up to 2 different streams per minute)"),
                ("Berserker", "🐺", 3, "Earn 3 points/message (max 1 per minute per stream, up to 2 different streams per minute)"),
                ("Raider", "🛶", 2, "Earn 2 points/message (max 1 per minute per stream, up to 2 different streams per minute)"),
                ("Thrall", "🪓", 1, "Earn 1 point/message (max 1 per minute per stream, up to 2 different streams per minute)")
            ]
            channel = discord.utils.get(bot.get_all_channels(), name="╡streams-live")
            if channel:
                # Delete previous bot messages in this channel
                async for msg in channel.history(limit=20):
                    if msg.author == bot.user:
                        try:
                            await msg.delete()
                        except Exception:
                            pass
                
                # Send new embeds
                for rank, icon, pts, desc in rank_order:
                    if rank in live_by_rank:
                        color = rank_colors.get(rank, 0x7289DA)
                        embed = Embed(
                            title=f"{icon} Currently Live {rank} Channels",
                            description=f"{desc}\n",
                            color=color
                        )
                        embed.set_footer(text=f"Last Updated • {datetime.now(timezone.utc).strftime('%b %d, %Y at %I:%M %p UTC')}")
                        
                        for discord_id, twitch_username in live_by_rank[rank]:
                            stream = stream_details.get(twitch_username)
                            if not stream:
                                continue
                            game = stream.get("game_name", "Unknown")
                            viewers = stream.get("viewer_count", "?")
                            started_at = stream.get("started_at")
                            
                            try:
                                start_dt = datetime.fromisoformat(started_at.replace("Z", "+00:00"))
                                now = datetime.now(timezone.utc)
                                duration = now - start_dt
                                hours, remainder = divmod(int(duration.total_seconds()), 3600)
                                minutes, _ = divmod(remainder, 60)
                                duration_str = f"{hours}h{minutes:02d}m" if hours else f"{minutes}m"
                            except Exception:
                                duration_str = "?"
                            
                            name = f"User({discord_id})"
                            for guild in bot.guilds:
                                member = guild.get_member(int(discord_id))
                                if member:
                                    name = member.display_name
                                    break
                            
                            embed.add_field(
                                name=f"[{name}](https://twitch.tv/{twitch_username})",
                                value=f"*{game}*\n👁️ {viewers} Viewers\n⏳ {duration_str}",
                                inline=True
                            )
                        
                        await channel.send(embed=embed)
            
            last_live_set = current_live_set.copy()

@tasks.loop(minutes=10)
async def health_check():
    """Periodic health check"""
    try:
        # Test database
        async with pool.acquire() as conn:
            await conn.execute("SELECT 1")
        
        # Test Twitch API
        if twitch_token:
            headers = {
                'Client-ID': config.twitch.client_id,
                'Authorization': f'Bearer {twitch_token}'
            }
            async with aiohttp.ClientSession() as session:
                async with session.get('https://api.twitch.tv/helix/users', headers=headers) as resp:
                    if resp.status == 401:
                        logger.warning("Twitch token expired, refreshing...")
                        await get_twitch_oauth_token()
        
        logger.debug("Health check passed")
        
    except Exception as e:
        logger.error(f"Health check failed: {e}")

@tasks.loop(hours=6)
async def cleanup_memory():
    """Periodic cleanup of unused data"""
    logger.info("Starting memory cleanup...")
    
    # Clean up empty stream chat counts
    empty_streams = [k for k, v in stream_chat_counts.items() if not v]
    for stream in empty_streams:
        stream_chat_counts.pop(stream, None)
    
    # Clean up old command rate limit data
    current_time = time.time()
    for user_id in list(user_command_times.keys()):
        user_history = user_command_times[user_id]
        # Remove entries older than 1 hour
        while user_history and user_history[0] < current_time - 3600:
            user_history.popleft()
        # Remove user entirely if no recent activity
        if not user_history:
            del user_command_times[user_id]
    
    logger.info(f"Memory cleanup completed - removed {len(empty_streams)} empty stream records")

# ---- ENHANCED HELPER FUNCTIONS ---- #
async def update_twitch_bot_channels():
    """Update Twitch bot channels when users link/unlink"""
    global twitch_bot_instance
    
    if not twitch_bot_instance:
        return
    
    try:
        # Get all linked users (username -> discord_id)
        current_users = await get_all_twitch_users()
        current_channels = set(current_users.keys())
        # Get channels bot is currently in
        connected_channels = set(channel.name for channel in twitch_bot_instance.connected_channels)
        # Join any new channels
        to_join = current_channels - connected_channels
        for channel in to_join:
            await twitch_bot_instance.join_channel(channel)
            logger.info(f"TwitchBot joined channel: {channel}")
        # Leave any channels that are no longer linked (should not happen, but for safety)
        to_leave = connected_channels - current_channels
        for channel in to_leave:
            await twitch_bot_instance.leave_channel(channel)
            logger.info(f"TwitchBot left channel: {channel}")
        # Always update the user mapping
        twitch_to_discord.clear()
        twitch_to_discord.update(current_users)
        logger.info(f"TwitchBot channel sync complete. Now in {len(current_channels)} channels.")
    except Exception as e:
        logger.error(f"Error updating Twitch bot channels: {e}")

async def setup_twitch_integration(twitch_username):
    """Handle Twitch API setup asynchronously"""
    try:
        if not twitch_token:
            await get_twitch_oauth_token()
        
        user_id = await get_twitch_user_id(twitch_username, twitch_token)
        if user_id:
            await subscribe_to_raid_events(user_id, twitch_token)
            logger.info(f"✅ Set up Twitch integration for {twitch_username}")
        else:
            logger.warning(f"Could not get Twitch user ID for {twitch_username}")
    except Exception as e:
        logger.error(f"Error setting up Twitch integration for {twitch_username}: {e}")

async def test_db_connection():
    """Enhanced database connection test"""
    max_retries = 3
    for attempt in range(max_retries):
        try:
            async with pool.acquire() as conn:
                result = await conn.fetchval("SELECT version()")
                logger.info(f"✅ Database connection successful - {result}")
                await conn.execute("SELECT 1")
                logger.info("✅ Database operations test passed")
                return True
        except Exception as e:
            logger.warning(f"Database connection attempt {attempt + 1} failed: {e}")
            if attempt == max_retries - 1:
                logger.error("❌ Database connection failed after all retries")
                raise
            await asyncio.sleep(2 ** attempt)  # Exponential backoff

# ---- DISCORD EVENT HANDLERS ---- #
@bot.event
async def on_ready():
    """Enhanced ready event with better initialization"""
    logger.info(f"✅ Discord bot logged in as {bot.user.name} (ID: {bot.user.id})")
    
    # Set bot status
    await bot.change_presence(
        status=discord.Status.online,
        activity=discord.Activity(
            type=discord.ActivityType.watching,
            name="Valhalla Warriors 🛡️"
        )
    )
    
    # Set nickname in all guilds
    for guild in bot.guilds:
        try:
            await guild.me.edit(nick="Valhalla Bot")
            logger.info(f"Set nickname in guild: {guild.name}")
        except discord.Forbidden:
            logger.warning(f"Cannot set nickname in guild: {guild.name} (insufficient permissions)")
        except Exception as e:
            logger.error(f"Error setting nickname in {guild.name}: {e}")
    
    # Sync slash commands
    try:
        if os.getenv("DEV_MODE", "false").lower() == "true":
            test_guild_id = os.getenv("TEST_GUILD_ID")
            if test_guild_id:
                guild = discord.Object(id=int(test_guild_id))
                synced = await bot.tree.sync(guild=guild)
                logger.info(f"✅ Synced {len(synced)} commands to test guild")
                # Also try global sync as backup
                try:
                    global_synced = await bot.tree.sync()
                    logger.info(f"✅ Also synced {len(global_synced)} commands globally as backup")
                except Exception as global_e:
                    logger.warning(f"Global sync backup failed: {global_e}")
            else:
                synced = await bot.tree.sync()
                logger.info(f"✅ Synced {len(synced)} commands globally (dev mode)")
        else:
            synced = await bot.tree.sync()
            logger.info(f"✅ Synced {len(synced)} slash commands globally")
    except Exception as e:
        logger.error(f"❌ Failed to sync slash commands: {e}")
        # Try emergency global sync
        try:
            emergency_synced = await bot.tree.sync()
            logger.info(f"⚠️ Emergency global sync: {len(emergency_synced)} commands")
        except Exception as emergency_e:
            logger.error(f"❌ Emergency sync also failed: {emergency_e}")
    
    # Start background tasks
    try:
        if not check_live_streams.is_running():
            check_live_streams.start()
            logger.info("✅ Started stream monitoring task")
        
        if not auto_post_currently_live.is_running():
            auto_post_currently_live.start()
            logger.info("✅ Started live streams posting task")
            
        if not health_check.is_running():
            health_check.start()
            logger.info("✅ Started health check task")
            
        if not cleanup_memory.is_running():
            cleanup_memory.start()
            logger.info("✅ Started memory cleanup task")
    except Exception as e:
        logger.error(f"❌ Failed to start background tasks: {e}")
    
    logger.info("🚀 ValhallaBot2 is fully operational!")

async def send_channel_welcome(member, dm_sent=False):
    """Send welcome message in channel (fallback or supplement to DM)"""
    # Find appropriate welcome channel
    welcome_channels = ['╡valhallabot-link', 'welcome', 'general']
    channel = None
    
    for channel_name in welcome_channels:
        channel = discord.utils.get(member.guild.text_channels, name=channel_name)
        if channel:
            break
    
    if not channel:
        return
    
    if dm_sent:
        # Brief public welcome when DM was successful
        embed = discord.Embed(
            title="🛡️ New Warrior Arrives!",
            description=f"Welcome {member.mention} to Valhalla Gaming! 🎮",
            color=0x00FF00
        )
        embed.add_field(
            name="Get Started",
            value=f"Link your Twitch account in this channel with `/linktwitch <username>` for **100 bonus points**!",
            inline=False
        )
    else:
        # Full welcome when DM failed
        embed = discord.Embed(
            title="🛡️ Welcome to Valhalla Gaming!",
            description=f"Welcome {member.mention}! Ready to join the ranks of Valhalla Warriors?",
            color=0xFFD700
        )
        embed.add_field(
            name="🎁 New Member Bonus",
            value="Link your Twitch account with `/linktwitch <username>` in the next 7 days for **100 bonus points**!",
            inline=False
        )
        embed.add_field(
            name="How It Works",
            value="Chat in member streams, raid fellow warriors, and climb the ranks from Thrall to Allfather! Use `/howtouse` for details.",
            inline=False
        )
    
    embed.set_thumbnail(url=member.display_avatar.url)
    
    try:
        await channel.send(embed=embed)
    except Exception as e:
        logger.error(f"Could not send channel welcome for {member.display_name}: {e}")

@bot.event
async def on_member_join(member):
    """Enhanced member join handler with DM welcome and bonus system"""
    logger.info(f"New member joined {member.guild.name}: {member.display_name}")
    
    # Send welcome DM with detailed explanation and bonus offer
    try:
        welcome_embed = discord.Embed(
            title="🛡️ Welcome to Valhalla Gaming!",
            description=f"Greetings {member.display_name}! You've entered the halls of Valhalla Warriors.",
            color=0xFFD700
        )
        
        welcome_embed.add_field(
            name="🎮 What is ValhallaBot?",
            value=(
                "Our community ranks warriors by how much they support each other's streams!\n"
                "• Chat in Valhalla streams to earn points\n"
                "• Raid fellow warriors for bonus points\n"
                "• Climb from Thrall to Allfather rank\n"
                "• Get featured when you go live!"
            ),
            inline=False
        )
        
        welcome_embed.add_field(
            name="🎁 LIMITED TIME: New Warrior Bonus!",
            value=(
                "**Link your Twitch account in the next 7 days and get 100 bonus points!**\n"
                f"Go to <#{discord.utils.get(member.guild.channels, name='╡valhallabot-link').id}> and use:\n"
                "`/linktwitch your_twitch_username`"
            ),
            inline=False
        )
        
        welcome_embed.add_field(
            name="🏆 The Rank System",
            value=(
                "🦾 **Allfather** - Top 5% (Earn 6 pts/chat)\n"
                "🛡️ **Chieftain** - Top 15% (Earn 5 pts/chat)\n"
                "🦅 **Jarl** - Top 30% (Earn 4 pts/chat)\n"
                "🐺 **Berserker** - Top 50% (Earn 3 pts/chat)\n"
                "🛶 **Raider** - Top 80% (Earn 2 pts/chat)\n"
                "🪓 **Thrall** - Everyone starts here (Earn 1 pt/chat)"
            ),
            inline=False
        )
        
        welcome_embed.add_field(
            name="📚 Need Help?",
            value=(
                "• Use `/howtouse` for a complete guide\n"
                "• Use `/help` to see all commands\n"
                "• Check out who's live in the streams channels!\n"
                "• Ask questions in general chat - we're friendly!"
            ),
            inline=False
        )
        
        welcome_embed.set_thumbnail(url=member.display_avatar.url)
        welcome_embed.set_footer(text="Link your Twitch within 7 days for 100 bonus points!")
        
        # Send DM
        await member.send(embed=welcome_embed)
        logger.info(f"✅ Sent welcome DM to {member.display_name}")
        
    except discord.Forbidden:
        logger.warning(f"Could not send DM to {member.display_name} - DMs disabled")
        # Fall back to channel welcome if DM fails
        await send_channel_welcome(member)
    except Exception as e:
        logger.error(f"Error sending welcome DM to {member.display_name}: {e}")
        await send_channel_welcome(member)
    
    # Also send a brief public welcome
    await send_channel_welcome(member, dm_sent=True)
    
    # Track join time for bonus eligibility
    try:
        async with pool.acquire() as conn:
            await conn.execute("""
                INSERT INTO users (discord_id, rank, points, created_at)
                VALUES ($1, 'Thrall', 0, NOW())
                ON CONFLICT (discord_id) DO NOTHING
            """, str(member.id))
    except Exception as e:
        logger.error(f"Error tracking join time for {member.display_name}: {e}")

@bot.event
async def on_app_command_error(interaction: discord.Interaction, error: app_commands.AppCommandError):
    """Handle slash command errors"""
    logger.error(f"Slash command error in {interaction.command}: {error}")
    
    error_msg = "❌ An error occurred while processing your command."
    
    if isinstance(error, app_commands.CommandOnCooldown):
        error_msg = f"⏰ Command is on cooldown. Try again in {error.retry_after:.1f} seconds."
    elif isinstance(error, app_commands.MissingPermissions):
        error_msg = "❌ You don't have permission to use this command."
    elif isinstance(error, app_commands.BotMissingPermissions):
        error_msg = "❌ I don't have the required permissions to execute this command."
    
    try:
        if not interaction.response.is_done():
            await interaction.response.send_message(error_msg, ephemeral=True)
        else:
            await interaction.followup.send(error_msg, ephemeral=True)
    except Exception as e:
        logger.error(f"Could not send error message: {e}")

# ---- SLASH COMMANDS ---- #
@bot.tree.command(name="linktwitch", description="Link your Discord to your Twitch account (admins can link for others)")
@app_commands.describe(
    twitch_username="Your Twitch username",
    user="(Admin only) Discord user to link this Twitch to"
)
async def linktwitch_slash(interaction: discord.Interaction, twitch_username: str, user: Optional[discord.User] = None):
    # ...existing code for linking user...
    # After linking, update TwitchBot channels
    await update_twitch_bot_channels()
    # ...existing code...
async def linktwitch_slash(
    interaction: discord.Interaction,
    twitch_username: str,
    user: discord.User = None
):
    try:
        # Rate limiting check
        if not await check_rate_limit(interaction.user.id):
            await interaction.response.send_message(
                "⏰ You're using commands too quickly. Please wait a moment.",
                ephemeral=True
            )
            return
            
        logger.info(f"linktwitch called by {interaction.user} for username: {twitch_username}")
        
        # Check if command is used in correct channel
        if interaction.channel is None or interaction.channel.name != "╡valhallabot-link":
            await interaction.response.send_message(
                "❌ You can only use this command in the ╡valhallabot-link channel.",
                ephemeral=True
            )
            return

        # Determine target user and check permissions
        if user is not None:
            is_admin = interaction.user.guild_permissions.administrator
            is_owner = interaction.user.id == interaction.guild.owner_id
            if not (is_admin or is_owner):
                await interaction.response.send_message(
                    "❌ Only admins or the server owner can link Twitch accounts for other users.",
                    ephemeral=True
                )
                return
            discord_id = str(user.id)
            target_mention = user.mention
            target_user = user
        else:
            discord_id = str(interaction.user.id)
            target_mention = interaction.user.mention
            target_user = interaction.user

        # Validate Twitch username
        twitch_username = twitch_username.lower().strip()
        if not twitch_username or len(twitch_username) > 25:
            await interaction.response.send_message(
                "❌ Invalid Twitch username. Must be 1-25 characters.",
                ephemeral=True
            )
            return
            
        if not twitch_username.replace("_", "").isalnum():
            await interaction.response.send_message(
                "❌ Invalid Twitch username. Please enter only letters, numbers, and underscores.",
                ephemeral=True
            )
            return

        # Check if Twitch username is already linked to another Discord user
        async with pool.acquire() as conn:
            existing_user = await conn.fetchrow(
                "SELECT discord_id FROM users WHERE twitch_username = $1 AND discord_id != $2", 
                twitch_username, discord_id
            )
            
            if existing_user:
                await interaction.response.send_message(
                    f"❌ Twitch username `{twitch_username}` is already linked to another Discord user.",
                    ephemeral=True
                )
                return

            # Check if user is eligible for new member bonus
            user_data = await conn.fetchrow(
                "SELECT twitch_username, created_at FROM users WHERE discord_id = $1", 
                discord_id
            )
            
            bonus_points = 0
            is_new_link = not user_data or not user_data['twitch_username']
            
            if is_new_link and user_data and user_data['created_at']:
                # Check if within 7 days of joining
                join_time = user_data['created_at']
                now = datetime.now(timezone.utc)
                days_since_join = (now - join_time.replace(tzinfo=timezone.utc)).days
                
                if days_since_join <= 7:
                    bonus_points = 100

            # Update or insert user
            await conn.execute(
                """
                INSERT INTO users (discord_id, twitch_username, rank, points)
                VALUES ($1, $2, 'Thrall', $3)
                ON CONFLICT (discord_id) DO UPDATE SET 
                    twitch_username = $2,
                    points = CASE 
                        WHEN users.twitch_username IS NULL THEN users.points + $3
                        ELSE users.points
                    END,
                    updated_at = NOW()
                """,
                discord_id, twitch_username, bonus_points
            )
            
            # Update rank if bonus points were awarded
            if bonus_points > 0:
                await update_user_rank(conn, discord_id)

        # Update global mapping
        twitch_to_discord[twitch_username] = discord_id

        # Send success response with bonus info
        success_message = f"✅ {target_mention}, your Twitch username `{twitch_username}` has been linked successfully!"
        if bonus_points > 0:
            success_message += f"\n🎁 **New Member Bonus**: You've been awarded {bonus_points} points!"

        await interaction.response.send_message(success_message, ephemeral=True)

        # Send public confirmation
        try:
            embed = discord.Embed(
                title="🔗 New Warrior Linked!",
                description=f"{target_mention} has joined the ranks of Valhalla Warriors!",
                color=0x00FF00
            )
            embed.add_field(
                name="Twitch Channel",
                value=f"[{twitch_username}](https://twitch.tv/{twitch_username})",
                inline=True
            )
            embed.add_field(
                name="Starting Rank",
                value="🪓 Thrall",
                inline=True
            )
            if bonus_points > 0:
                embed.add_field(
                    name="New Member Bonus",
                    value=f"🎁 {bonus_points} points awarded!",
                    inline=True
                )
                embed.color = 0xFFD700  # Gold for bonus
            
            embed.set_thumbnail(url=target_user.display_avatar.url)
            embed.timestamp = datetime.now(timezone.utc)
            
            await interaction.followup.send(embed=embed)
        except Exception as e:
            logger.error(f"Could not send public confirmation: {e}")

        # Update Twitch bot channels
        await update_twitch_bot_channels()

        # Handle Twitch API integration (non-blocking)
        asyncio.create_task(setup_twitch_integration(twitch_username))

    except Exception as e:
        logger.error(f"Error in /linktwitch: {e}")
        traceback.print_exc()
        if not interaction.response.is_done():
            await interaction.response.send_message("❌ An error occurred. Please try again later.", ephemeral=True)

@bot.tree.command(name="unlinktwitch", description="Unlink your Twitch account (admins can unlink for others)")
@app_commands.describe(user="(Admin only) Discord user to unlink")
async def unlinktwitch_slash(interaction: discord.Interaction, user: discord.User = None):
    try:
        # Rate limiting check
        if not await check_rate_limit(interaction.user.id):
            await interaction.response.send_message(
                "⏰ You're using commands too quickly. Please wait a moment.",
                ephemeral=True
            )
            return
            
        # Determine target user and check permissions
        if user is not None:
            is_admin = interaction.user.guild_permissions.administrator
            is_owner = interaction.user.id == interaction.guild.owner_id
            if not (is_admin or is_owner):
                await interaction.response.send_message(
                    "❌ Only admins or the server owner can unlink Twitch accounts for other users.",
                    ephemeral=True
                )
                return
            discord_id = str(user.id)
            target_mention = user.mention
        else:
            discord_id = str(interaction.user.id)
            target_mention = interaction.user.mention

        async with pool.acquire() as conn:
            row = await conn.fetchrow("SELECT twitch_username FROM users WHERE discord_id = $1", discord_id)
            if not row or not row["twitch_username"]:
                await interaction.response.send_message(
                    f"❌ {target_mention} does not have a linked Twitch account.",
                    ephemeral=True
                )
                return

            old_username = row["twitch_username"]
            await conn.execute("UPDATE users SET twitch_username = NULL, updated_at = NOW() WHERE discord_id = $1", discord_id)

        # Remove from global mapping
        twitch_to_discord.pop(old_username, None)

        await interaction.response.send_message(
            f"✅ {target_mention}'s Twitch account (`{old_username}`) has been unlinked.",
            ephemeral=True
        )

        # Update Twitch bot channels
        await update_twitch_bot_channels()

    except Exception as e:
        logger.error(f"Error in /unlinktwitch: {e}")
        if not interaction.response.is_done():
            await interaction.response.send_message("❌ An error occurred. Please try again later.", ephemeral=True)

@bot.tree.command(name="rank", description="Show your current Valhalla rank")
@app_commands.describe(user="Check another user's rank (optional)")
async def rank_slash(interaction: discord.Interaction, user: discord.User = None):
    try:
        # Rate limiting check
        if not await check_rate_limit(interaction.user.id):
            await interaction.response.send_message(
                "⏰ You're using commands too quickly. Please wait a moment.",
                ephemeral=True
            )
            return
            
        target_user = user if user else interaction.user
        discord_id = str(target_user.id)
        
        async with pool.acquire() as conn:
            row = await conn.fetchrow("SELECT rank, points, twitch_username FROM users WHERE discord_id = $1", discord_id)
        
        if not row:
            await interaction.response.send_message(
                f"❌ {target_user.mention} hasn't linked their Twitch account yet. Use `/linktwitch` to get started!",
                ephemeral=True
            )
            return

        rank = row["rank"]
        points = row["points"]
        twitch_username = row["twitch_username"]
        icon = rank_icons.get(rank, "")
        color = rank_colors.get(rank, 0x7289DA)

        embed = discord.Embed(
            title=f"{icon} {target_user.display_name}'s Rank",
            color=color
        )
        embed.add_field(name="Current Rank", value=f"{icon} **{rank}**", inline=True)
        embed.add_field(name="Points", value=f"**{points:,}**", inline=True)
        if twitch_username:
            embed.add_field(name="Twitch", value=f"[{twitch_username}](https://twitch.tv/{twitch_username})", inline=True)
        embed.set_thumbnail(url=target_user.display_avatar.url)
        embed.timestamp = datetime.now(timezone.utc)

        await interaction.response.send_message(embed=embed, ephemeral=True)

    except Exception as e:
        logger.error(f"Error in /rank: {e}")
        await interaction.response.send_message("❌ An error occurred. Please try again later.", ephemeral=True)

@bot.tree.command(name="mypoints", description="Show your current points and detailed stats")
async def mypoints_slash(interaction: discord.Interaction):
    try:
        # Rate limiting check
        if not await check_rate_limit(interaction.user.id):
            await interaction.response.send_message(
                "⏰ You're using commands too quickly. Please wait a moment.",
                ephemeral=True
            )
            return
            
        discord_id = str(interaction.user.id)
        
        async with pool.acquire() as conn:
            # Get user info
            user_row = await conn.fetchrow("SELECT points, rank, twitch_username FROM users WHERE discord_id = $1", discord_id)
            
            if not user_row:
                await interaction.response.send_message("❌ You haven't linked your Twitch account yet. Use `/linktwitch` to get started!", ephemeral=True)
                return

            # Get user's position in leaderboard
            position = await conn.fetchval(
                "SELECT COUNT(*) + 1 FROM users WHERE points > $1",
                user_row["points"]
            )
            
            # Get total users
            total_users = await conn.fetchval("SELECT COUNT(*) FROM users WHERE points > 0")
            
            # Get recent activity
            recent_raids = await conn.fetchval(
                "SELECT COUNT(*) FROM raids WHERE raider_id = $1 AND timestamp > NOW() - INTERVAL '7 days'",
                discord_id
            )
            
            recent_chat_points = await conn.fetchval(
                "SELECT COALESCE(SUM(points_awarded), 0) FROM chat_points WHERE chatter_id = $1 AND timestamp > NOW() - INTERVAL '7 days'",
                discord_id
            )

        points = user_row["points"]
        rank = user_row["rank"]
        twitch_username = user_row["twitch_username"]
        icon = rank_icons.get(rank, "")
        color = rank_colors.get(rank, 0x7289DA)

        embed = discord.Embed(
            title=f"💰 {interaction.user.display_name}'s Valhalla Stats",
            color=color
        )
        embed.add_field(name="Total Points", value=f"**{points:,}**", inline=True)
        embed.add_field(name="Current Rank", value=f"{icon} **{rank}**", inline=True)
        embed.add_field(name="Leaderboard Position", value=f"**#{position}** of {total_users}", inline=True)
        embed.add_field(name="Recent Activity (7 days)", value=f"🗡️ **{recent_raids}** raids sent\n💬 **{recent_chat_points}** chat points earned", inline=False)
        if twitch_username:
            embed.add_field(name="Twitch Channel", value=f"[twitch.tv/{twitch_username}](https://twitch.tv/{twitch_username})", inline=False)
        embed.set_thumbnail(url=interaction.user.display_avatar.url)
        embed.timestamp = datetime.now(timezone.utc)

        await interaction.response.send_message(embed=embed, ephemeral=True)

    except Exception as e:
        logger.error(f"Error in /mypoints: {e}")
        await interaction.response.send_message("❌ An error occurred. Please try again later.", ephemeral=True)

@bot.tree.command(name="leaderboard", description="Show the top warriors")
@app_commands.describe(limit="Number of users to show (max 50)")
async def leaderboard_slash(interaction: discord.Interaction, limit: int = 20):
    try:
        # Rate limiting check
        if not await check_rate_limit(interaction.user.id):
            await interaction.response.send_message(
                "⏰ You're using commands too quickly. Please wait a moment.",
                ephemeral=True
            )
            return
            
        # Validate limit
        limit = max(1, min(limit, 50))
        
        async with pool.acquire() as conn:
            rows = await conn.fetch(
                "SELECT discord_id, rank, points, twitch_username FROM users WHERE points > 0 ORDER BY points DESC LIMIT $1",
                limit
            )
        
        if not rows:
            await interaction.response.send_message("📉 No leaderboard data yet.", ephemeral=True)
            return

        embed = discord.Embed(
            title="🏆 Valhalla's Mightiest Warriors",
            description=f"Top {len(rows)} warriors by points",
            color=0xFFD700
        )

        leaderboard_text = ""
        for i, row in enumerate(rows, 1):
            discord_id = row["discord_id"]
            rank = row["rank"]
            points = row["points"]
            
            # Get display name
            name = f"User({discord_id})"
            try:
                member = interaction.guild.get_member(int(discord_id))
                if member:
                    name = member.display_name
            except:
                pass
            
            icon = rank_icons.get(rank, "")
            
            # Add medal emojis for top 3
            if i == 1:
                medal = "🥇"
            elif i == 2:
                medal = "🥈"
            elif i == 3:
                medal = "🥉"
            else:
                medal = f"**{i}.**"
            
            leaderboard_text += f"{medal} {icon} **{name}** • {points:,} pts\n"

        embed.description = leaderboard_text
        embed.set_footer(text=f"Use '/leaderboard <number>' to see more • Updated {datetime.now(timezone.utc).strftime('%H:%M UTC')}")

        await interaction.response.send_message(embed=embed)

    except Exception as e:
        logger.error(f"Error in /leaderboard: {e}")
        await interaction.response.send_message("❌ An error occurred. Please try again later.", ephemeral=True)

@bot.tree.command(name="stats", description="Show detailed Valhalla Warrior stats")
@app_commands.describe(user="View another user's stats (optional)")
async def stats_slash(interaction: discord.Interaction, user: discord.User = None):
    try:
        # Rate limiting check
        if not await check_rate_limit(interaction.user.id):
            await interaction.response.send_message(
                "⏰ You're using commands too quickly. Please wait a moment.",
                ephemeral=True
            )
            return
            
        target_user = user if user else interaction.user
        discord_id = str(target_user.id)
        
        async with pool.acquire() as conn:
            # Get user info
            user_row = await conn.fetchrow("SELECT rank, points, twitch_username FROM users WHERE discord_id = $1", discord_id)
            
            if not user_row:
                await interaction.response.send_message(
                    f"❌ {target_user.mention} hasn't linked their Twitch account yet.",
                    ephemeral=True
                )
                return

            # Top 3 members they support (by chat count)
            support_rows = await conn.fetch("""
                SELECT u.discord_id, u.twitch_username, c.count 
                FROM chats c
                JOIN users u ON c.streamer_id = u.discord_id
                WHERE c.chatter_id = $1
                ORDER BY c.count DESC
                LIMIT 3
            """, discord_id)

            # Top 3 supporters (by chat count)
            supporter_rows = await conn.fetch("""
                SELECT u.discord_id, u.twitch_username, c.count 
                FROM chats c
                JOIN users u ON c.chatter_id = u.discord_id
                WHERE c.streamer_id = $1
                ORDER BY c.count DESC
                LIMIT 3
            """, discord_id)

            # Raid stats
            raids_sent = await conn.fetchval(
                "SELECT COUNT(*) FROM raids WHERE raider_id = $1",
                discord_id
            )
            raids_received = await conn.fetchval(
                "SELECT COUNT(*) FROM raids WHERE target_id = $1",
                discord_id
            )

        rank = user_row["rank"]
        color = rank_colors.get(rank, 0x7289DA)
        icon = rank_icons.get(rank, "")

        embed = discord.Embed(
            title=f"{icon} {target_user.display_name}'s Warrior Stats",
            color=color,
            description="Detailed community engagement statistics"
        )

        # Support given
        if support_rows:
            support_list = []
            for row in support_rows:
                name = f"User({row['discord_id']})"
                try:
                    member = interaction.guild.get_member(int(row['discord_id']))
                    if member:
                        name = member.display_name
                except:
                    pass
                support_list.append(f"**{name}** • {row['count']} chats")
            embed.add_field(
                name="🤝 Top Streamers Supported",
                value="\n".join(support_list),
                inline=False
            )
        else:
            embed.add_field(name="🤝 Top Streamers Supported", value="No chat data yet", inline=False)

        # Support received
        if supporter_rows:
            supporter_list = []
            for row in supporter_rows:
                name = f"User({row['discord_id']})"
                try:
                    member = interaction.guild.get_member(int(row['discord_id']))
                    if member:
                        name = member.display_name
                except:
                    pass
                supporter_list.append(f"**{name}** • {row['count']} chats")
            embed.add_field(
                name="💪 Top Supporters",
                value="\n".join(supporter_list),
                inline=False
            )
        else:
            embed.add_field(name="💪 Top Supporters", value="No supporters yet", inline=False)

        # Raid stats
        embed.add_field(
            name="⚔️ Raid Statistics",
            value=f"**Raids Sent:** {raids_sent}\n**Raids Received:** {raids_received}",
            inline=True
        )

        # Additional info
        embed.add_field(
            name="📊 Current Status",
            value=f"**Rank:** {icon} {rank}\n**Points:** {user_row['points']:,}",
            inline=True
        )

        embed.set_thumbnail(url=target_user.display_avatar.url)
        embed.timestamp = datetime.now(timezone.utc)

        await interaction.response.send_message(embed=embed, ephemeral=True)

    except Exception as e:
        logger.error(f"Error in /stats: {e}")
        await interaction.response.send_message("❌ An error occurred. Please try again later.", ephemeral=True)

@bot.tree.command(name="refer", description="Refer a new streamer to earn bonus points")
@app_commands.describe(user="Discord user, username, or Twitch username you are referring")
async def refer_slash(interaction: discord.Interaction, user: str):
    try:
        # Rate limiting check
        if not await check_rate_limit(interaction.user.id):
            await interaction.response.send_message(
                "⏰ You're using commands too quickly. Please wait a moment.",
                ephemeral=True
            )
            return
            
        referrer_id = str(interaction.user.id)
        
        async with pool.acquire() as conn:
            # Check if referrer is linked
            referrer_check = await conn.fetchrow("SELECT 1 FROM users WHERE discord_id = $1", referrer_id)
            if not referrer_check:
                await interaction.response.send_message(
                    "❌ You must link your Twitch account first before referring others. Use `/linktwitch`.",
                    ephemeral=True
                )
                return

            referred_id = None

            # Try Discord mention
            if user.startswith("<@") and user.endswith(">"):
                referred_id = user.strip("<@!>")
            else:
                # Try Discord username (case-insensitive)
                for guild_member in interaction.guild.members:
                    if (
                        user.lower() == guild_member.name.lower()
                        or user.lower() == f"{guild_member.name.lower()}#{guild_member.discriminator}"
                        or user.lower() == guild_member.display_name.lower()
                    ):
                        referred_id = str(guild_member.id)
                        break
                
                # If not found, try Twitch username
                if not referred_id:
                    row = await conn.fetchrow("SELECT discord_id FROM users WHERE twitch_username = $1", user.lower())
                    if row:
                        referred_id = row["discord_id"]

            if not referred_id:
                await interaction.response.send_message("❌ Could not find that user. Make sure they're in this server or have linked their Twitch account.", ephemeral=True)
                return

            if referred_id == referrer_id:
                await interaction.response.send_message("❌ You cannot refer yourself!", ephemeral=True)
                return

            # Check if referred user exists in database
            user_row = await conn.fetchrow("SELECT twitch_username FROM users WHERE discord_id = $1", referred_id)
            
            if not user_row:
                # User not linked yet
                mention = f"<@{referred_id}>"
                embed = discord.Embed(
                    title="🎯 You've Been Referred!",
                    description=f"{mention}, {interaction.user.mention} has referred you to join Valhalla Warriors!",
                    color=0x00FF00
                )
                embed.add_field(
                    name="Next Steps",
                    value="Link your Twitch account with `/linktwitch <your_twitch_username>` to activate the referral.",
                    inline=False
                )
                embed.add_field(
                    name="Referral Benefits",
                    value="• Your referrer will earn **200 points** when you reach 300 points\n• You'll be part of an amazing gaming community!",
                    inline=False
                )
                
                await interaction.response.send_message(embed=embed)
                return

            if not user_row["twitch_username"]:
                await interaction.response.send_message("❌ That user needs to link their Twitch account first before they can be referred.", ephemeral=True)
                return

            # Check if referral already exists
            exists = await conn.fetchrow(
                "SELECT 1 FROM referrals WHERE referrer_id = $1 AND referred_id = $2",
                referrer_id, referred_id
            )
            
            if exists:
                await interaction.response.send_message("❌ You have already referred this user.", ephemeral=True)
                return

            # Create referral record
            await conn.execute(
                "INSERT INTO referrals (referrer_id, referred_id) VALUES ($1, $2)",
                referrer_id, referred_id
            )

        await interaction.response.send_message(
            "✅ Referral recorded successfully! You'll receive **200 points** when they reach 300 points.",
            ephemeral=True
        )

    except Exception as e:
        logger.error(f"Error in /refer: {e}")
        await interaction.response.send_message("❌ An error occurred. Please try again later.", ephemeral=True)

@bot.tree.command(name="newmember_stats", description="View new member onboarding statistics (Admin only)")
@app_commands.describe(days="Number of days to look back (default: 30)")
async def newmember_stats_slash(interaction: discord.Interaction, days: int = 30):
    try:
        # Check if user has admin permissions
        if not (interaction.user.guild_permissions.administrator or interaction.user.id == interaction.guild.owner_id):
            await interaction.response.send_message(
                "❌ This command is restricted to administrators.",
                ephemeral=True
            )
            return

        # Validate days parameter
        days = max(1, min(days, 365))  # Between 1 and 365 days
        
        async with pool.acquire() as conn:
            # Get new members in the specified timeframe
            new_members = await conn.fetch("""
                SELECT 
                    discord_id,
                    twitch_username,
                    points,
                    rank,
                    created_at,
                    updated_at,
                    CASE 
                        WHEN twitch_username IS NOT NULL THEN 'linked'
                        ELSE 'not_linked'
                    END as status,
                    CASE 
                        WHEN twitch_username IS NOT NULL AND updated_at - created_at <= INTERVAL '7 days' THEN 'bonus_eligible'
                        ELSE 'no_bonus'
                    END as bonus_status
                FROM users 
                WHERE created_at > NOW() - INTERVAL '%s days'
                ORDER BY created_at DESC
            """ % days)
            
            # Calculate statistics
            total_new_members = len(new_members)
            linked_members = [m for m in new_members if m['status'] == 'linked']
            bonus_recipients = [m for m in new_members if m['bonus_status'] == 'bonus_eligible' and m['points'] >= 100]
            
            # Time-based analysis
            within_24h = [m for m in linked_members if m['updated_at'] - m['created_at'] <= timedelta(hours=24)]
            within_7d = [m for m in linked_members if m['updated_at'] - m['created_at'] <= timedelta(days=7)]
            
            # Current rank distribution of new members
            rank_distribution = {}
            for member in linked_members:
                rank = member['rank']
                rank_distribution[rank] = rank_distribution.get(rank, 0) + 1

        if total_new_members == 0:
            await interaction.response.send_message(
                f"📊 No new members found in the last {days} days.",
                ephemeral=True
            )
            return

        # Calculate percentages
        link_rate = (len(linked_members) / total_new_members) * 100 if total_new_members > 0 else 0
        bonus_rate = (len(bonus_recipients) / total_new_members) * 100 if total_new_members > 0 else 0
        quick_link_rate = (len(within_24h) / total_new_members) * 100 if total_new_members > 0 else 0

        # Create comprehensive stats embed
        embed = discord.Embed(
            title="📊 New Member Onboarding Statistics",
            description=f"Analysis of the last {days} days",
            color=0x00FF00
        )

        # Overview stats
        embed.add_field(
            name="📈 Overview",
            value=(
                f"**Total New Members:** {total_new_members}\n"
                f"**Linked Accounts:** {len(linked_members)} ({link_rate:.1f}%)\n"
                f"**Bonus Recipients:** {len(bonus_recipients)} ({bonus_rate:.1f}%)\n"
                f"**Quick Linkers (<24h):** {len(within_24h)} ({quick_link_rate:.1f}%)"
            ),
            inline=False
        )

        # Conversion funnel
        embed.add_field(
            name="🎯 Conversion Funnel",
            value=(
                f"👥 {total_new_members} joined server\n"
                f"🔗 {len(linked_members)} linked Twitch ({link_rate:.1f}%)\n"
                f"⚡ {len(within_24h)} linked within 24h ({quick_link_rate:.1f}%)\n"
                f"📅 {len(within_7d)} linked within 7 days\n"
                f"🎁 {len(bonus_recipients)} received bonus"
            ),
            inline=True
        )

        # Rank progression of new members
        if rank_distribution:
            rank_order = ["Allfather", "Chieftain", "Jarl", "Berserker", "Raider", "Thrall"]
            rank_text = []
            for rank in rank_order:
                count = rank_distribution.get(rank, 0)
                if count > 0:
                    icon = rank_icons.get(rank, "")
                    rank_text.append(f"{icon} {rank}: {count}")
            
            embed.add_field(
                name="🏆 Current Ranks",
                value="\n".join(rank_text) if rank_text else "No linked members yet",
                inline=True
            )

        # Engagement insights
        if linked_members:
            avg_points = sum(m['points'] for m in linked_members) / len(linked_members)
            most_active = max(linked_members, key=lambda x: x['points'])
            
            # Get Discord user for most active
            most_active_name = f"User({most_active['discord_id']})"
            try:
                member = interaction.guild.get_member(int(most_active['discord_id']))
                if member:
                    most_active_name = member.display_name
            except:
                pass
            
            embed.add_field(
                name="💪 Engagement",
                value=(
                    f"**Average Points:** {avg_points:.0f}\n"
                    f"**Most Active:** {most_active_name}\n"
                    f"**Their Points:** {most_active['points']:,}\n"
                    f"**Their Rank:** {rank_icons.get(most_active['rank'], '')} {most_active['rank']}"
                ),
                inline=False
            )

        # Recent activity (last 5 new linked members)
        recent_links = [m for m in linked_members if m['status'] == 'linked'][-5:]
        if recent_links:
            recent_text = []
            for member in reversed(recent_links):  # Most recent first
                member_name = f"User({member['discord_id']})"
                try:
                    discord_member = interaction.guild.get_member(int(member['discord_id']))
                    if discord_member:
                        member_name = discord_member.display_name
                except:
                    pass
                
                time_diff = datetime.now(timezone.utc) - member['updated_at'].replace(tzinfo=timezone.utc)
                if time_diff.days > 0:
                    time_str = f"{time_diff.days}d ago"
                elif time_diff.seconds > 3600:
                    time_str = f"{time_diff.seconds // 3600}h ago"
                else:
                    time_str = f"{time_diff.seconds // 60}m ago"
                
                bonus_indicator = "🎁" if member['bonus_status'] == 'bonus_eligible' and member['points'] >= 100 else ""
                recent_text.append(f"{bonus_indicator} **{member_name}** ({time_str})")
            
            embed.add_field(
                name="🕒 Recent Links",
                value="\n".join(recent_text),
                inline=False
            )

        # Success tips based on data
        tips = []
        if link_rate < 30:
            tips.append("💡 Link rate is low - consider promoting the bonus more")
        if quick_link_rate > 50:
            tips.append("🚀 Great job! Many members link quickly")
        if len(bonus_recipients) < len(within_7d):
            tips.append("🎁 Some eligible members may not have received bonus points")
        
        if tips:
            embed.add_field(
                name="💭 Insights",
                value="\n".join(tips),
                inline=False
            )

        embed.set_footer(text=f"Data from last {days} days • Use /newmember_stats <days> for different timeframes")
        embed.timestamp = datetime.now(timezone.utc)

        await interaction.response.send_message(embed=embed, ephemeral=True)

    except Exception as e:
        logger.error(f"Error in /newmember_stats: {e}")
        await interaction.response.send_message("❌ An error occurred while fetching statistics.", ephemeral=True)

@bot.tree.command(name="award_missing_bonus", description="Award bonus points to eligible members who missed it (Admin only)")
async def award_missing_bonus_slash(interaction: discord.Interaction):
    try:
        # Check admin permissions
        if not (interaction.user.guild_permissions.administrator or interaction.user.id == interaction.guild.owner_id):
            await interaction.response.send_message("❌ Admin only command.", ephemeral=True)
            return

        async with pool.acquire() as conn:
            # Find eligible members who linked within 7 days but have less than 100 points
            eligible_members = await conn.fetch("""
                SELECT discord_id, twitch_username, points, created_at, updated_at
                FROM users 
                WHERE twitch_username IS NOT NULL 
                AND updated_at - created_at <= INTERVAL '7 days'
                AND points < 100
                AND created_at > NOW() - INTERVAL '30 days'
            """)
            
            awarded_count = 0
            for member in eligible_members:
                discord_id = member['discord_id']
                current_points = member['points']
                bonus_needed = 100 - current_points
                
                await conn.execute(
                    "UPDATE users SET points = points + $1 WHERE discord_id = $2",
                    bonus_needed, discord_id
                )
                await update_user_rank(conn, discord_id)
                awarded_count += 1
        
        if awarded_count > 0:
            await interaction.response.send_message(
                f"✅ Awarded missing bonus points to {awarded_count} eligible members!",
                ephemeral=True
            )
        else:
            await interaction.response.send_message(
                "ℹ️ No eligible members found who are missing bonus points.",
                ephemeral=True
            )

    except Exception as e:
        logger.error(f"Error in /award_missing_bonus: {e}")
        await interaction.response.send_message("❌ An error occurred.", ephemeral=True)

@bot.tree.command(name="help", description="Show all ValhallaBot commands")
async def help_slash(interaction: discord.Interaction):
    embed = discord.Embed(
        title="⚔️ ValhallaBot Command Guide",
        description="Here are all available commands:",
        color=0x7289DA
    )
    embed.add_field(name="/linktwitch <username>", value="Link your Twitch account", inline=False)
    embed.add_field(name="/rank [user]", value="Show rank (yours or someone else's)", inline=False)
    embed.add_field(name="/mypoints", value="Show your detailed stats", inline=False)
    embed.add_field(name="/leaderboard [limit]", value="Show top warriors", inline=False)
    embed.add_field(name="/stats [user]", value="Show detailed warrior stats", inline=False)
    embed.add_field(name="/refer <user>", value="Refer someone to earn bonus points", inline=False)
    embed.add_field(name="/howtouse", value="Complete guide on using the bot", inline=False)
    embed.add_field(name="/unlinktwitch", value="Unlink your Twitch account", inline=False)
    embed.add_field(name="/addpoints <user> <points>", value="(Admin) Award/deduct points", inline=False)
    embed.add_field(name="/newmember_stats", value="(Admin) View onboarding statistics", inline=False)
    embed.set_footer(text="🛡️ Fight. Raid. Rank up. Valhalla is watching.")
    
    await interaction.response.send_message(embed=embed, ephemeral=True)

@bot.tree.command(name="howtouse", description="Show comprehensive guide on using ValhallaBot")
async def how_to_use_slash(interaction: discord.Interaction):
    embed = discord.Embed(
        title="⚔️ HOW TO USE VALHALLABOT",
        description="Your path to glory in the Valhalla Gaming Discord",
        color=0xFFD700
    )

    embed.add_field(
        name="🧩 Step 1: Link Your Twitch",
        value="Use `/linktwitch <your_twitch_username>` to connect your Discord and Twitch.\n> Example: `/linktwitch odinstreams`\n🎁 **New members get 100 bonus points if linked within 7 days!**",
        inline=False
    )

    embed.add_field(
        name="🗡️ Step 2: Earn Points",
        value="• 💬 Chat in Valhalla streams (up to 100 pts/streamer every 48h)\n"
              "• ⚔️ Raid Valhalla members (10 pts per viewer, up to 5x/month per target)\n"
              "• 🎯 Refer new members (200 pts when they reach 300 points)",
        inline=False
    )

    embed.add_field(
        name="📈 Step 3: Climb the Ranks",
        value="Ranks auto-update based on your percentile:\n"
              "• 🦾 Allfather – Top 5% (6 pts/chat)\n"
              "• 🛡️ Chieftain – 5–15% (5 pts/chat)\n"
              "• 🦅 Jarl – 15–30% (4 pts/chat)\n"
              "• 🐺 Berserker – 30–50% (3 pts/chat)\n"
              "• 🛶 Raider – 50–80% (2 pts/chat)\n"
              "• 🪓 Thrall – Bottom 20% (1 pt/chat)",
        inline=False
    )

    embed.add_field(
        name="🔍 Commands",
        value="• `/rank` – Show your rank\n"
              "• `/mypoints` – View your points\n"
              "• `/leaderboard` – Top 50 warriors\n"
              "• `/stats` – See your support stats\n"
              "• `/refer <user>` – Refer new members\n"
              "• `/help` – Full command list",
        inline=False
    )

    embed.add_field(
        name="📣 Going Live?",
        value="ValhallaBot will post in **#now-live** when you stream — game, viewers, rank, and link!\nAfter your stream ends, you'll get a summary of all the support you received.",
        inline=False
    )

    embed.set_footer(text="🛡️ Fight. Raid. Rank up. Valhalla is watching.")
    embed.timestamp = datetime.utcnow()

    await interaction.response.send_message(embed=embed, ephemeral=True)

@bot.tree.command(name="addpoints", description="Award points to a specific user (Admin only)")
@app_commands.describe(
    user="The Discord user to award points to",
    points="Number of points to add (can be negative to subtract)",
    reason="Reason for awarding points (optional)"
)
async def addpoints_slash(
    interaction: discord.Interaction,
    user: discord.User,
    points: int,
    reason: str = None
):
    try:
        # Check admin permissions
        is_admin = interaction.user.guild_permissions.administrator
        is_owner = interaction.user.id == interaction.guild.owner_id
        if not (is_admin or is_owner):
            await interaction.response.send_message(
                "❌ You don't have permission to use this command. Only administrators can award points.",
                ephemeral=True
            )
            return

        # Rate limiting check
        if not await check_rate_limit(interaction.user.id):
            await interaction.response.send_message(
                "⏰ You're using commands too quickly. Please wait a moment.",
                ephemeral=True
            )
            return

        # Validate points input
        if points == 0:
            await interaction.response.send_message(
                "❌ Points must be a non-zero number.",
                ephemeral=True
            )
            return

        if abs(points) > 10000:
            await interaction.response.send_message(
                "❌ Points must be between -10,000 and 10,000.",
                ephemeral=True
            )
            return

        discord_id = str(user.id)

        async with pool.acquire() as conn:
            # Check if user exists in database
            user_row = await conn.fetchrow(
                "SELECT points, rank, twitch_username FROM users WHERE discord_id = $1",
                discord_id
            )

            if not user_row:
                # Create new user entry if they don't exist
                await conn.execute("""
                    INSERT INTO users (discord_id, rank, points, created_at)
                    VALUES ($1, 'Thrall', 0, NOW())
                """, discord_id)
                old_points = 0
                old_rank = "Thrall"
                twitch_username = None
            else:
                old_points = user_row["points"]
                old_rank = user_row["rank"]
                twitch_username = user_row["twitch_username"]

            # Calculate new points (ensure they don't go below 0)
            new_points = max(0, old_points + points)
            actual_points_added = new_points - old_points

            # Update points
            await conn.execute(
                "UPDATE users SET points = $1, last_activity = NOW() WHERE discord_id = $2",
                new_points, discord_id
            )

            # Update rank based on new points
            await update_user_rank(conn, discord_id)

            # Get new rank after update
            updated_row = await conn.fetchrow(
                "SELECT rank FROM users WHERE discord_id = $1",
                discord_id
            )
            new_rank = updated_row["rank"] if updated_row else "Thrall"

            # Log the action in audit log
            action_details = {
                "points_added": actual_points_added,
                "old_points": old_points,
                "new_points": new_points,
                "old_rank": old_rank,
                "new_rank": new_rank,
                "target_user": f"{user.display_name} ({user.id})",
                "reason": reason or "No reason provided"
            }

            await conn.execute(
                "INSERT INTO audit_log (user_id, action, details) VALUES ($1, $2, $3)",
                str(interaction.user.id),
                "admin_points_awarded",
                json.dumps(action_details)
            )

        # Create response embed
        action_text = "awarded" if actual_points_added > 0 else "deducted"
        embed = discord.Embed(
            title="💰 Points Updated",
            color=0x00FF00 if actual_points_added > 0 else 0xFF4500
        )

        embed.add_field(
            name="User",
            value=f"{user.mention} ({user.display_name})",
            inline=True
        )

        embed.add_field(
            name="Points Change",
            value=f"{'+' if actual_points_added > 0 else ''}{actual_points_added:,}",
            inline=True
        )

        embed.add_field(
            name="New Total",
            value=f"{new_points:,} points",
            inline=True
        )

        if old_rank != new_rank:
            embed.add_field(
                name="Rank Change",
                value=f"{old_rank} → **{new_rank}**",
                inline=False
            )

        if twitch_username:
            embed.add_field(
                name="Twitch Account",
                value=f"[{twitch_username}](https://twitch.tv/{twitch_username})",
                inline=True
            )

        if reason:
            embed.add_field(
                name="Reason",
                value=reason,
                inline=False
            )

        embed.add_field(
            name="Admin",
            value=interaction.user.mention,
            inline=True
        )

        embed.timestamp = datetime.utcnow()
        embed.set_footer(text="Admin action logged in audit trail")

        await interaction.response.send_message(embed=embed, ephemeral=True)

        # Send notification to bot-commands channel
        try:
            channel = discord.utils.get(interaction.guild.text_channels, name="╡bot-commands")
            if channel:
                public_embed = discord.Embed(
                    title="⚖️ Admin Point Award",
                    color=0xFFD700,
                    description=f"An admin has {'awarded' if actual_points_added > 0 else 'deducted'} points!"
                )
                
                public_embed.add_field(
                    name="Recipient",
                    value=user.mention,
                    inline=True
                )
                
                public_embed.add_field(
                    name="Points",
                    value=f"{'+' if actual_points_added > 0 else ''}{actual_points_added:,}",
                    inline=True
                )
                
                public_embed.add_field(
                    name="New Total",
                    value=f"{new_points:,}",
                    inline=True
                )
                
                if old_rank != new_rank:
                    public_embed.add_field(
                        name="Rank Update",
                        value=f"{old_rank} → **{new_rank}**",
                        inline=False
                    )
                
                if reason:
                    public_embed.add_field(
                        name="Reason",
                        value=reason,
                        inline=False
                    )
                
                public_embed.timestamp = datetime.utcnow()
                await channel.send(embed=public_embed)
                
        except Exception as e:
            logger.error(f"Failed to send public notification: {e}")

        logger.info(f"Admin {interaction.user} awarded {actual_points_added} points to {user} (reason: {reason or 'None'})")

    except Exception as e:
        logger.error(f"Error in /addpoints: {e}")
        traceback.print_exc()
        if not interaction.response.is_done():
            await interaction.response.send_message(
                "❌ An error occurred while awarding points. Please try again.",
                ephemeral=True
            )

# ---- WEBHOOK SERVER SETUP ---- #
async def setup_webhook_server():
    """Setup the webhook server for Twitch EventSub"""
    global web_app, web_runner
    
    logger.info("Setting up webhook server...")
    
    web_app = web.Application()
    web_app.router.add_routes(routes)
    
    web_runner = web.AppRunner(web_app)
    await web_runner.setup()
    
    site = web.TCPSite(web_runner, '0.0.0.0', config.webhook.port)
    await site.start()
    
    logger.info(f"✅ Webhook server started on port {config.webhook.port}")

# ---- GRACEFUL SHUTDOWN ---- #
async def shutdown_handler():
    """Handle graceful shutdown"""
    logger.info("Shutting down ValhallaBot...")
    
    # Stop background tasks
    try:
        if check_live_streams.is_running():
            check_live_streams.stop()
        if auto_post_currently_live.is_running():
            auto_post_currently_live.stop()
        if health_check.is_running():
            health_check.stop()
        if cleanup_memory.is_running():
            cleanup_memory.stop()
        logger.info("✅ Background tasks stopped")
    except Exception as e:
        logger.error(f"Error stopping background tasks: {e}")
    
    # Close Twitch bot
    try:
        if twitch_bot_instance:
            await twitch_bot_instance.close()
        logger.info("✅ Twitch bot closed")
    except Exception as e:
        logger.error(f"Error closing Twitch bot: {e}")
    
    # Close TwitchIO v3 Chat Bot
    try:
        if twitch_bot_instance:
            await twitch_bot_instance.close()
        logger.info("✅ Twitch chat bot closed")
    except Exception as e:
        logger.error(f"Error closing Twitch chat bot: {e}")
    
    # Close web server
    try:
        if web_runner:
            await web_runner.cleanup()
        logger.info("✅ Web server closed")
    except Exception as e:
        logger.error(f"Error closing web server: {e}")
    
    # Close database pool
    try:
        if pool:
            await pool.close()
        logger.info("✅ Database pool closed")
    except Exception as e:
        logger.error(f"Error closing database pool: {e}")
    
    # Close Discord bot
    try:
        await bot.close()
        logger.info("✅ Discord bot closed")
    except Exception as e:
        logger.error(f"Error closing Discord bot: {e}")

def signal_handler(signum, frame):
    """Handle shutdown signals"""
    logger.info(f"Received signal {signum}, initiating shutdown...")
    asyncio.create_task(shutdown_handler())

# ---- MAIN FUNCTION ---- #
async def main():
    """Main startup function"""
    global pool, twitch_bot_instance, twitch_token
    
    try:
        # Initialize database connection pool
        logger.info("Connecting to database...")
        await db_manager.initialize(
            config.database.url,
            min_size=config.database.pool_min_size,
            max_size=config.database.pool_max_size,
            command_timeout=config.database.command_timeout
        )
        pool = db_manager.pool
        
        # Initialize all components
        await initialize_database()
        twitch_token = await get_twitch_oauth_token()
        await setup_webhook_server()
        
        # Start Discord bot
        discord_task = asyncio.create_task(bot.start(config.discord.bot_token))
        
        # Start background tasks
        if not check_live_streams.is_running():
            check_live_streams.start()
        if not auto_post_currently_live.is_running():
            auto_post_currently_live.start()
            
        # Setup signal handlers
        for sig in (signal.SIGTERM, signal.SIGINT):
            signal.signal(sig, signal_handler)
            
        # Keep running until interrupted
        try:
            await discord_task
        except asyncio.CancelledError:
            await shutdown_handler()
            
    except Exception as e:
        logger.error(f"❌ Fatal error in main(): {e}")
        traceback.print_exc()
        await shutdown_handler()
        raise

# ---- PROGRAM ENTRY POINT ---- #
if __name__ == "__main__":
    try:
        logger.info("🛡️ Starting ValhallaBot2...")
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Received keyboard interrupt, shutting down...")
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        traceback.print_exc()
        sys.exit(1)
    finally:
        logger.info("ValhallaBot2 shutdown complete")