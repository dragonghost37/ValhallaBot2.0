#!/usr/bin/env python3
"""
Configuration management for ValhallaBot2
Handles environment variables and configuration validation
"""

import os
from typing import Dict, Any, Optional
from dataclasses import dataclass
import logging

logger = logging.getLogger(__name__)

@dataclass
class DatabaseConfig:
    url: str
    pool_min_size: int = 5
    pool_max_size: int = 20
    command_timeout: int = 60

@dataclass
class DiscordConfig:
    bot_token: str
    guild_id: Optional[str] = None

@dataclass
class TwitchConfig:
    client_id: str
    client_secret: str
    eventsub_secret: str
    api_timeout: int = 30

@dataclass
class WebhookConfig:
    url: str
    port: int = 8080
    max_payload_size: int = 1024 * 1024  # 1MB
    secret: str = ""

@dataclass
class MonitoringConfig:
    log_level: str = "INFO"
    metrics_enabled: bool = True

@dataclass
class Config:
    environment: str
    database: DatabaseConfig
    discord: DiscordConfig
    twitch: TwitchConfig
    webhook: WebhookConfig
    monitoring: MonitoringConfig
    
    def _validate_environment(self):
        """Validate all required environment variables are set"""
        required_vars = [
            'DATABASE_URL',
            'DISCORD_BOT_TOKEN', 
            'TWITCH_CLIENT_ID',
            'TWITCH_CLIENT_SECRET',
            'TWITCH_EVENTSUB_SECRET',
            'WEBHOOK_URL'
        ]
        
        missing_vars = []
        for var in required_vars:
            if not os.getenv(var):
                missing_vars.append(var)
        
        if missing_vars:
            raise ValueError(f"Missing required environment variables: {', '.join(missing_vars)}")
        
        logger.info("✅ All required environment variables are set")

def create_config() -> Config:
    """Create configuration from environment variables"""
    return Config(
        environment=os.getenv('ENVIRONMENT', 'development'),
        database=DatabaseConfig(
            url=os.getenv('DATABASE_URL', ''),
            pool_min_size=int(os.getenv('DB_POOL_MIN_SIZE', '5')),
            pool_max_size=int(os.getenv('DB_POOL_MAX_SIZE', '20')),
            command_timeout=int(os.getenv('DB_COMMAND_TIMEOUT', '60'))
        ),
        discord=DiscordConfig(
            bot_token=os.getenv('DISCORD_BOT_TOKEN', ''),
            guild_id=os.getenv('DISCORD_GUILD_ID')
        ),
        twitch=TwitchConfig(
            client_id=os.getenv('TWITCH_CLIENT_ID', ''),
            client_secret=os.getenv('TWITCH_CLIENT_SECRET', ''),
            eventsub_secret=os.getenv('TWITCH_EVENTSUB_SECRET', ''),
            api_timeout=int(os.getenv('TWITCH_API_TIMEOUT', '30'))
        ),
        webhook=WebhookConfig(
            url=os.getenv('WEBHOOK_URL', ''),
            port=int(os.getenv('WEBHOOK_PORT', '8080')),
            max_payload_size=int(os.getenv('WEBHOOK_MAX_PAYLOAD_SIZE', str(1024 * 1024))),
            secret=os.getenv('WEBHOOK_SECRET', os.getenv('TWITCH_EVENTSUB_SECRET', ''))
        ),
        monitoring=MonitoringConfig(
            log_level=os.getenv('LOG_LEVEL', 'INFO'),
            metrics_enabled=os.getenv('METRICS_ENABLED', 'true').lower() == 'true'
        )
    )

# Global config instance
config = create_config()
