#!/usr/bin/env python3
"""
ValhallaBot2 Start Script for Render
This script starts the bot with proper error handling and logging for cloud deployment.
"""

import os
import sys
import asyncio
import logging
from pathlib import Path

# Add current directory to Python path
sys.path.insert(0, str(Path(__file__).parent))

# Configure logging for cloud deployment
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)  # Only stdout for Render
    ]
)

logger = logging.getLogger(__name__)

def validate_environment():
    """Validate required environment variables are set"""
    required_vars = [
        "DISCORD_BOT_TOKEN",
        "TWITCH_CLIENT_ID",
        "TWITCH_CLIENT_SECRET",
        "DATABASE_URL"
    ]
    
    missing = []
    for var in required_vars:
        if not os.getenv(var):
            missing.append(var)
    
    if missing:
        logger.error(f"Missing required environment variables: {', '.join(missing)}")
        return False
    
    logger.info("✅ All required environment variables are set")
    return True

async def start_bot():
    """Start the bot with error handling"""
    try:
        # Import and run the main bot
        from ValhallaBot2 import main
        logger.info("🛡️ Starting ValhallaBot2...")
        await main()
    except KeyboardInterrupt:
        logger.info("Bot stopped by user")
    except Exception as e:
        logger.error(f"Fatal error starting bot: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    # Validate environment before starting
    if not validate_environment():
        sys.exit(1)
    
    # Start the bot
    try:
        asyncio.run(start_bot())
    except Exception as e:
        logger.error(f"Failed to start bot: {e}")
        sys.exit(1)
