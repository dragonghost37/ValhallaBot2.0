#!/usr/bin/env python3
import sys
import time
import json
import traceback
import signal

# --- Added missing imports and definitions --- #
import asyncio
import os
import uuid
from datetime import datetime, timezone
from collections import defaultdict, deque
from typing import Optional, Any, Dict, Set, Deque, DefaultDict, List, Tuple, Callable, Coroutine


# Third-party libraries
import discord
from discord.ext import commands, tasks
from discord import Embed
import aiohttp
import asyncpg
from aiohttp import web


# Project modules
import config
import db_manager
import error_handling as error_handler
import security
import monitoring
from security import create_security_config, SecurityMiddleware, WebhookSecurity, security_auditor
from error_handling import ErrorSeverity, ValidationError, APIError, DatabaseError
from validators import InputValidator


# Retry decorator and config (assume defined in error_handling or utils)
try:
    from error_handling import with_retry, RetryConfig
except ImportError:
    def with_retry(*args, **kwargs):
        def decorator(f):
            return f
        return decorator
    class RetryConfig:
        def __init__(self, max_attempts=3, base_delay=1.0):
            pass


# API manager (assume defined in monitoring or elsewhere)
try:
    from monitoring import api_manager
except ImportError:
    api_manager = None

import logging
log_level = logging.INFO
# ...existing code...
logging.basicConfig(
    level=log_level,
    format='%(asctime)s - %(name)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s',
    handlers=[
        logging.FileHandler('valhallabot.log', encoding='utf-8'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# Suppress noisy third-party loggers only if in production, else let them be
if getattr(config, 'environment', 'development') == "production":
    for noisy in ['discord', 'aiohttp', 'asyncpg']:
        try:
            logging.getLogger(noisy).setLevel(logging.WARNING)
        except Exception:
            pass

logger.info(f"🛡️ ValhallaBot2.py starting up in {getattr(config, 'environment', 'development')} mode...")

# ---- CONFIGURATION ---- #

# Use config module, but do not force exit on validation failure or use protected attributes
try:
    validate_env = getattr(config, 'validate_environment', None)
    if callable(validate_env):
        validate_env()
        logger.info("✅ Configuration validated successfully")
except Exception as e:
    logger.warning(f"⚠️ Configuration validation failed: {e} (continuing anyway)")

# Initialize security configuration (allow fallback if missing)
try:
    security_config = create_security_config()
    security_middleware = SecurityMiddleware(security_config)
    webhook_secret = getattr(security_config, 'webhook_secret', 'fallbacksecret')
    webhook_security = WebhookSecurity(webhook_secret)
except Exception as e:
    logger.warning(f"⚠️ Security config failed: {e} (using minimal security)")
    security_config = None
    security_middleware = None
    webhook_security = None

# Initialize database manager (allow fallback if config missing)
try:
    db_url = getattr(getattr(config, 'database', None), 'url', None)
    if db_url:
        db_manager.database_url = db_url
    else:
        logger.warning("⚠️ Database URL missing in config; database features may not work.")
except Exception as e:
    logger.warning(f"⚠️ Database config missing: {e}")

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


# Global variables with type hints

from typing import Set, Dict, Deque, DefaultDict, Any, List, Tuple
import asyncpg
pool: Any = None
twitch_bot_instance = None
web_app = None
web_runner = None
twitch_token = None
currently_live: Set[str] = set()
stream_chat_counts: Dict[str, Dict[str, int]] = {}
twitch_to_discord: Dict[str, str] = {}
stream_raids: Dict[str, List[Tuple[str, int, int]]] = {}
stream_raids_sent: Dict[str, List[Tuple[str, int, int]]] = {}
last_live_set: Set[str] = set()

# Rate limiting for commands
user_command_times: DefaultDict[int, Deque[float]] = defaultdict(lambda: deque(maxlen=10))

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
                json.dumps({"environment": getattr(config, 'environment', 'production'), "timestamp": datetime.now(timezone.utc).isoformat()})
            )
            
            logger.info("✅ Production database schema initialized successfully")
            if monitoring and hasattr(monitoring, 'metrics'):
                monitoring.metrics.increment_counter("database_operations_total", labels={"operation": "initialize", "status": "success"})
            
        finally:
            if hasattr(db_manager, 'pool') and db_manager.pool:
                await db_manager.pool.release(conn)
            
    except Exception as e:
        logger.error(f"❌ Database initialization failed: {e}")
        if monitoring and hasattr(monitoring, 'metrics'):
            monitoring.metrics.increment_counter("database_operations_total", labels={"operation": "initialize", "status": "error"})
        if error_handler and hasattr(error_handler, 'handle_error'):
            error_handler.handle_error(e, "database_initialization", severity=ErrorSeverity.CRITICAL)
        raise DatabaseError(f"Database initialization failed: {e}")

# ---- PRODUCTION TWITCH INTEGRATION ---- #
@with_retry(RetryConfig(max_attempts=3, base_delay=1.0))
async def get_all_twitch_users() -> Dict[str, str]:
    """Get all linked Twitch usernames and their Discord IDs from database with validation"""
    request_id = str(uuid.uuid4())
    if monitoring and hasattr(monitoring, 'performance_monitor'):
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
            if monitoring and hasattr(monitoring, 'metrics'):
                monitoring.metrics.set_gauge("active_twitch_users", len(user_map))
            if monitoring and hasattr(monitoring, 'performance_monitor'):
                monitoring.performance_monitor.end_request(request_id, True)
            return user_map
        finally:
            if hasattr(db_manager, 'pool') and db_manager.pool:
                await db_manager.pool.release(conn)
    except Exception as e:
        logger.error(f"Failed to get Twitch users: {e}")
        if error_handler and hasattr(error_handler, 'handle_error'):
            error_handler.handle_error(e, "get_all_twitch_users")
        if monitoring and hasattr(monitoring, 'performance_monitor'):
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
        if monitoring and hasattr(monitoring, 'metrics'):
            monitoring.metrics.increment_counter("twitch_auth_requests", labels={"status": "success"})
        
        return token
        
    except Exception as e:
        logger.error(f"Failed to get Twitch OAuth token: {e}")
        if monitoring and hasattr(monitoring, 'metrics'):
            monitoring.metrics.increment_counter("twitch_auth_requests", labels={"status": "error"})
        if error_handler and hasattr(error_handler, 'handle_error'):
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
            if monitoring and hasattr(monitoring, 'metrics'):
                monitoring.metrics.increment_counter("twitch_user_lookups", labels={"status": "not_found"})
            return None
        
        user_id = response_data['data'][0]['id']
        
        # Validate user ID format
        if not user_id or not user_id.isdigit():
            raise APIError(f"Invalid user ID received: {user_id}")
        
        logger.info(f"✅ Got Twitch user ID for {validated_username}: {user_id}")
        if monitoring and hasattr(monitoring, 'metrics'):
            monitoring.metrics.increment_counter("twitch_user_lookups", labels={"status": "success"})
        return user_id
        
    except Exception as e:
        logger.error(f"❌ Failed to get user ID for {validated_username}: {e}")
        if monitoring and hasattr(monitoring, 'metrics'):
            monitoring.metrics.increment_counter("twitch_user_lookups", labels={"status": "error"})
        if error_handler and hasattr(error_handler, 'handle_error'):
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
        if monitoring and hasattr(monitoring, 'metrics'):
            monitoring.metrics.increment_counter("twitch_subscriptions", labels={"type": "raid", "status": "success"})
        return True
        
    except Exception as e:
        logger.error(f"❌ Failed to subscribe to raid events for user {user_id}: {e}")
        if monitoring and hasattr(monitoring, 'metrics'):
            monitoring.metrics.increment_counter("twitch_subscriptions", labels={"type": "raid", "status": "error"})
        if error_handler and hasattr(error_handler, 'handle_error'):
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
            if monitoring and hasattr(monitoring, 'metrics'):
                monitoring.metrics.increment_counter("webhook_requests", labels={"status": "invalid_signature"})
            if monitoring and hasattr(monitoring, 'performance_monitor'):
                monitoring.performance_monitor.end_request(request_id, False)
            raise web.HTTPForbidden(text="Invalid signature")
        
        # Parse JSON payload
        try:
            payload = json.loads(raw_payload.decode('utf-8'))
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            logger.error(f"Invalid JSON payload from {client_ip}: {e}")
            if monitoring and hasattr(monitoring, 'metrics'):
                monitoring.metrics.increment_counter("webhook_requests", labels={"status": "invalid_json"})
            if monitoring and hasattr(monitoring, 'performance_monitor'):
                monitoring.performance_monitor.end_request(request_id, False)
            raise web.HTTPBadRequest(text="Invalid JSON")
        
        # Handle challenge verification
        if "challenge" in payload:
            challenge = payload["challenge"]
            logger.info(f"EventSub challenge received from {client_ip}")
            if monitoring and hasattr(monitoring, 'metrics'):
                monitoring.metrics.increment_counter("webhook_requests", labels={"status": "challenge"})
            if monitoring and hasattr(monitoring, 'performance_monitor'):
                monitoring.performance_monitor.end_request(request_id, True)
            return web.Response(text=challenge, content_type="text/plain")
        
        # Process raid events
        if payload.get("subscription", {}).get("type") == "channel.raid":
            await process_raid_event(payload, client_ip, request_id)
        else:
            logger.info(f"Unhandled EventSub type: {payload.get('subscription', {}).get('type')}")
        
        if monitoring and hasattr(monitoring, 'metrics'):
            monitoring.metrics.increment_counter("webhook_requests", labels={"status": "success"})
        if monitoring and hasattr(monitoring, 'performance_monitor'):
            monitoring.performance_monitor.end_request(request_id, True)
        return web.Response(status=200)
        
    except web.HTTPException:
        raise
    except Exception as e:
        logger.error(f"EventSub handler error: {e}")
        if error_handler and hasattr(error_handler, 'handle_error'):
            error_handler.handle_error(e, "eventsub_handler")
        if monitoring and hasattr(monitoring, 'metrics'):
            monitoring.metrics.increment_counter("webhook_requests", labels={"status": "error"})
        if monitoring and hasattr(monitoring, 'performance_monitor'):
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
            if monitoring and hasattr(monitoring, 'metrics'):
                monitoring.metrics.increment_counter("raids_processed", labels={
                    "raider_found": str(bool(raider_row)),
                    "target_found": str(bool(target_row)),
                    "points_awarded": str(points_awarded > 0)
                })
                monitoring.metrics.record_histogram("raid_viewers", viewers)
                monitoring.metrics.record_histogram("raid_points_awarded", points_awarded)
            
        finally:
            if hasattr(db_manager, 'pool') and db_manager.pool:
                await db_manager.pool.release(conn)
            
    except ValidationError as e:
        logger.warning(f"Invalid raid event data: {e}")
        if monitoring and hasattr(monitoring, 'metrics'):
            monitoring.metrics.increment_counter("raid_validation_errors")
    except Exception as e:
        logger.error(f"Error processing raid event: {e}")
        if error_handler and hasattr(error_handler, 'handle_error'):
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
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "version": "2.0.0-production",
            "environment": getattr(config, 'environment', 'production'),
            "checks": overall_health["checks"]
        }, status=status_code)
        
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return web.json_response({
            "status": "error",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "error": str(e)
        }, status=503)

@routes.get("/health/live")
async def liveness_probe(request: web.Request) -> web.Response:
    """Kubernetes liveness probe endpoint"""
    try:
        # Basic liveness check - just verify the service is responding
        return web.json_response({
            "status": "alive",
            "timestamp": datetime.now(timezone.utc).isoformat(),
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
            "timestamp": datetime.now(timezone.utc).isoformat(),
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
        status_report = monitoring.get_status_report() if monitoring and hasattr(monitoring, 'get_status_report') else {}
        security_summary = security_auditor.get_security_summary() if security_auditor and hasattr(security_auditor, 'get_security_summary') else {}
        error_summary = error_handler.get_error_summary() if error_handler and hasattr(error_handler, 'get_error_summary') else {}
        
        return web.json_response({
            "service": "ValhallaBot",
            "version": "2.0.0-production",
            "environment": getattr(config, 'environment', 'production'),
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
            if hasattr(db_manager, 'pool') and db_manager.pool:
                await db_manager.pool.release(conn)
    except Exception:
        return False

def check_discord_ready() -> bool:
    """Check if Discord bot is ready"""
    global bot
    return bot.is_ready() if 'bot' in globals() else False

async def check_twitch_ready() -> bool:
    """Check if Twitch integration is ready"""
    try:
        token = await get_twitch_oauth_token()
        return bool(token)
    except Exception:
        return False

# ---- AWARD & RANK FUNCTIONS ---- #
async def award_chat_points(conn: asyncpg.Connection, chatter_discord_id, streamer_twitch_username, count=1):
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

async def update_user_rank(conn: asyncpg.Connection, discord_id):
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
            # Join all channels in the list, and rejoin if disconnected
            for channel in self.channels_to_join:
                if channel not in [c.name for c in self.connected_channels]:
                    await self.join_channels([channel])
            logger.info(f"TwitchBot joined channels: {self.channels_to_join}")
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

async def setup_webhook_server():
    global web_app, web_runner
    logger.info("Setting up webhook server...")
    web_app = web.Application(middlewares=[security_middleware] if security_middleware else [])
    web_app.add_routes(routes)
    web_runner = web.AppRunner(web_app)
    await web_runner.setup()
    site = web.TCPSite(web_runner, '0.0.0.0', 8080)
    await site.start()
    logger.info("✅ Webhook server started on port 8080")

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
                        if resp.status == 401:
                            # Token expired, refresh and retry once
                            logger.warning("Twitch token expired, refreshing...")
                            new_token = await get_twitch_oauth_token()
                            if new_token:
                                globals()['twitch_token'] = new_token
                                headers['Authorization'] = f'Bearer {new_token}'
                                async with session.get(url, headers=headers) as resp2:
                                    data = await resp2.json()
                                    if data.get('data'):
                                        stream = data['data'][0]
                                        live_now.add(twitch_username)
                                        stream_info[twitch_username] = {
                                            'game_name': stream.get('game_name', 'Unknown'),
                                            'title': stream.get('title', ''),
                                            'viewer_count': stream.get('viewer_count', 0)
                                        }
                            else:
                                logger.error("Failed to refresh Twitch token.")
                        else:
                            data = await resp.json()
                            if data.get('data'):
                                stream = data['data'][0]
                                live_now.add(twitch_username)
                                stream_info[twitch_username] = {
                                    'game_name': stream.get('game_name', 'Unknown'),
                                    'title': stream.get('title', ''),
                                    'viewer_count': stream.get('viewer_count', 0)
                                }
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
                title=f"\nᚱᚢᚾᛁᚲᚱᚢᚾᛁᚲ\n{user_obj.display_name} is now LIVE on Twitch!\nᚱᚢᚾᛁᚲᚱᚢᚾᛁᚲ\n",
                color=color,
                description=f"**Valhalla Gaming Rank:** {rank}\n"
                            f"🎮 **Game:** {stream.get('game_name')}\n"
                            f"📺 **Title:** {stream.get('title')}\n"
                            f"👁️ **Viewers:** {stream.get('viewer_count')}\n"
                            f"🔗 [Watch here](https://twitch.tv/{twitch_username})"
            )
            embed.timestamp = datetime.now(timezone.utc)
            embed.set_footer(text="\nᚠᚢᚾᛖᚱᚨᛚᚠᚢᚾᛖᚱᚨᛚ\nMay Odin guide your stream!\nᚠᚢᚾᛖᚱᚨᛚᚠᚢᚾᛖᚱᚨᛚ\n")
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
                title=f"\nᚱᚢᚾᛁᚲᚱᚢᚾᛁᚲ\n{streamer_name}'s Stream Summary\nᚱᚢᚾᛁᚲᚱᚢᚾᛁᚲ\n",
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
            embed.set_footer(text="\nᚠᚢᚾᛖᚱᚨᛚᚠᚢᚾᛖᚱᚨᛚ\nSkål for your efforts in Valhalla!\nᚠᚢᚾᛖᚱᚨᛚᚠᚢᚾᛖᚱᚨᛚ\n")

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
    
    live_by_rank = {}
    current_live_set = set()
    live_now = set()
    stream_info = {}
    async with pool.acquire() as conn:
        users = await conn.fetch("SELECT discord_id, twitch_username, rank FROM users WHERE twitch_username IS NOT NULL")
        for user in users:
            twitch_username = user["twitch_username"]
            discord_id = user["discord_id"]
            rank = user["rank"]
            twitch_to_discord[twitch_username] = discord_id
            live_by_rank.setdefault(rank, []).append((discord_id, twitch_username))

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
                        data = await resp.json()
                        if data.get('data'):
                            stream = data['data'][0]
                            live_now.add(twitch_username)
                            current_live_set.add(twitch_username)
                            stream_info[twitch_username] = {
                                'game_name': stream.get('game_name', 'Unknown'),
                                'title': stream.get('title', ''),
                                'viewer_count': stream.get('viewer_count', 0),
                                'started_at': stream.get('started_at', '')
                            }
                except Exception as e:
                    logger.error(f"Error checking stream status for {twitch_username}: {e}")
        
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
                            stream = stream_info.get(twitch_username)
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
                                minutes = remainder // 60
                                duration_str = f"{hours}h {minutes}m" if hours > 0 else f"{minutes}m"
                            except Exception as e:
                                logger.error(f"Error parsing stream start time for {twitch_username}: {e}")
                                duration_str = "?"
                            

                            embed.add_field(
                                name=f"{discord_id}",
                                value=(
                                    f"**{game}**\n"
                                    f"👁️ {viewers} viewers\n"
                                    f"⏱️ Live for {duration_str}\n"
                                    f"🔗 [Watch here](https://twitch.tv/{twitch_username})"
                                ),
                                inline=False
                            )
                        
                        await channel.send(embed=embed)
            
            last_live_set = current_live_set.copy()

            # After processing, update last_live_set
            last_live_set = current_live_set.copy()

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
        if hasattr(db_manager, 'pool') and db_manager.pool:
            await db_manager.close_pool()
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
        db_url = getattr(getattr(config, 'database', None), 'url', None) or os.getenv('DATABASE_URL')
        if not db_url:
            raise ValueError("Database URL not configured")
        
        db_manager.database_url = db_url
        await db_manager.init_pool()
        pool = db_manager.pool
        
        # Initialize all components
        await initialize_database()
        twitch_token = await get_twitch_oauth_token()
        await setup_webhook_server()
        
        # Start Discord bot
        bot_token = getattr(getattr(config, 'discord', None), 'bot_token', None) or os.getenv('DISCORD_BOT_TOKEN')
        if not bot_token:
            raise ValueError("Discord bot token not configured")
        
        discord_task = asyncio.create_task(bot.start(bot_token))
        
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