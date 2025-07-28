#!/usr/bin/env python3
"""
Input validation and sanitization for ValhallaBot2
Provides secure validation for all user inputs
"""

import re
import html
from typing import Optional, List, Dict, Any
import logging

logger = logging.getLogger(__name__)

class ValidationError(Exception):
    """Custom exception for validation errors"""
    pass

class InputValidator:
    """Input validation utility class"""
    
    # Regex patterns for validation
    DISCORD_ID_PATTERN = re.compile(r'^[0-9]{17,19}$')
    TWITCH_USERNAME_PATTERN = re.compile(r'^[a-zA-Z0-9_]{4,25}$')
    
    @staticmethod
    def validate_discord_id(discord_id: str) -> str:
        """Validate Discord ID format"""
        if not discord_id or not isinstance(discord_id, str):
            raise ValidationError("Discord ID must be a non-empty string")
        
        discord_id = discord_id.strip()
        if not InputValidator.DISCORD_ID_PATTERN.match(discord_id):
            raise ValidationError("Invalid Discord ID format")
        
        return discord_id
    
    @staticmethod
    def validate_twitch_username(username: str) -> str:
        """Validate Twitch username format"""
        if not username or not isinstance(username, str):
            raise ValidationError("Twitch username must be a non-empty string")
        
        username = username.lower().strip()
        if not InputValidator.TWITCH_USERNAME_PATTERN.match(username):
            raise ValidationError("Invalid Twitch username format (4-25 chars, letters/numbers/underscore only)")
        
        return username
    
    @staticmethod
    def validate_points(points: Any) -> int:
        """Validate points value"""
        try:
            points = int(points)
            if points < 0:
                raise ValidationError("Points cannot be negative")
            if points > 1000000:  # 1M point cap
                raise ValidationError("Points value too large")
            return points
        except (ValueError, TypeError):
            raise ValidationError("Points must be a valid number")
    
    @staticmethod
    def validate_channel_name(channel_name: str) -> str:
        """Validate Discord channel name"""
        if not channel_name or not isinstance(channel_name, str):
            raise ValidationError("Channel name must be a non-empty string")
        
        channel_name = channel_name.strip()
        if len(channel_name) > 100:
            raise ValidationError("Channel name too long")
        
        return channel_name
    
    @staticmethod
    def sanitize_user_input(user_input: str, max_length: int = 1000) -> str:
        """Sanitize user input for safe display"""
        if not user_input:
            return ""
        
        # HTML escape
        sanitized = html.escape(str(user_input))
        
        # Truncate if too long
        if len(sanitized) > max_length:
            sanitized = sanitized[:max_length] + "..."
        
        return sanitized
    
    @staticmethod
    def validate_embed_field(name: str, value: str) -> tuple[str, str]:
        """Validate Discord embed field content"""
        if not name or len(name) > 256:
            raise ValidationError("Embed field name must be 1-256 characters")
        
        if not value or len(value) > 1024:
            raise ValidationError("Embed field value must be 1-1024 characters")
        
        return InputValidator.sanitize_user_input(name, 256), InputValidator.sanitize_user_input(value, 1024)

class SQLSanitizer:
    """SQL injection prevention utilities"""
    
    @staticmethod
    def sanitize_table_name(table_name: str) -> str:
        """Sanitize table name for dynamic queries"""
        if not re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', table_name):
            raise ValidationError("Invalid table name")
        return table_name
    
    @staticmethod
    def sanitize_column_name(column_name: str) -> str:
        """Sanitize column name for dynamic queries"""
        if not re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', column_name):
            raise ValidationError("Invalid column name")
        return column_name
    
    @staticmethod
    def validate_order_direction(direction: str) -> str:
        """Validate SQL ORDER BY direction"""
        direction = direction.upper().strip()
        if direction not in ('ASC', 'DESC'):
            raise ValidationError("Order direction must be ASC or DESC")
        return direction
