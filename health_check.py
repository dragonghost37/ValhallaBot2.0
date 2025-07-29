#!/usr/bin/env python3
"""
ValhallaBot2 Health Check Script
This script verifies that the bot is running correctly and all systems are operational.
"""

import asyncio
import asyncpg
import aiohttp
import os
import sys
import json
from datetime import datetime
from pathlib import Path

# Add the project root to Python path
sys.path.insert(0, str(Path(__file__).parent))

class HealthChecker:
    def __init__(self):
        self.results = {}
        self.overall_status = True
        
    def log_check(self, check_name, status, message=""):
        """Log the result of a health check."""
        self.results[check_name] = {
            "status": "PASS" if status else "FAIL",
            "message": message,
            "timestamp": datetime.utcnow().isoformat()
        }
        
        if not status:
            self.overall_status = False
            
        status_emoji = "✅" if status else "❌"
        print(f"{status_emoji} {check_name}: {message}")
    
    async def check_environment_variables(self):
        """Check that all required environment variables are set."""
        required_vars = [
            "DISCORD_BOT_TOKEN",
            "TWITCH_CLIENT_ID", 
            "TWITCH_CLIENT_SECRET",
            "DATABASE_URL"
        ]
        
        missing_vars = []
        for var in required_vars:
            if not os.getenv(var):
                missing_vars.append(var)
        
        if missing_vars:
            self.log_check(
                "Environment Variables",
                False,
                f"Missing: {', '.join(missing_vars)}"
            )
        else:
            self.log_check(
                "Environment Variables",
                True,
                "All required variables present"
            )
    
    async def check_database_connection(self):
        """Check database connectivity and basic operations."""
        try:
            database_url = os.getenv("DATABASE_URL")
            if not database_url:
                self.log_check("Database Connection", False, "DATABASE_URL not set")
                return
            
            conn = await asyncpg.connect(database_url)
            
            # Test basic query
            result = await conn.fetchval("SELECT 1")
            if result == 1:
                self.log_check("Database Connection", True, "Connection successful")
            else:
                self.log_check("Database Connection", False, "Query returned unexpected result")
                
            # Check if users table exists
            table_exists = await conn.fetchval("""
                SELECT EXISTS (
                    SELECT FROM information_schema.tables 
                    WHERE table_schema = 'public' 
                    AND table_name = 'users'
                );
            """)
            
            if table_exists:
                self.log_check("Database Schema", True, "Users table exists")
                
                # Test inserting/updating a user (health check user)
                await conn.execute("""
                    INSERT INTO users (discord_id, username, points, rank) 
                    VALUES ($1, $2, $3, $4)
                    ON CONFLICT (discord_id) 
                    DO UPDATE SET username = $2
                """, 999999999999999999, "healthcheck", 0, "Thrall")
                
                self.log_check("Database Operations", True, "Insert/update operations working")
                
            else:
                self.log_check("Database Schema", False, "Users table not found")
            
            await conn.close()
            
        except Exception as e:
            self.log_check("Database Connection", False, f"Error: {str(e)}")
    
    async def check_discord_api(self):
        """Check Discord API accessibility."""
        try:
            token = os.getenv("DISCORD_BOT_TOKEN")
            if not token:
                self.log_check("Discord API", False, "DISCORD_BOT_TOKEN not set")
                return
            
            headers = {
                "Authorization": f"Bot {token}",
                "User-Agent": "ValhallaBot2 Health Check"
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.get("https://discord.com/api/v10/users/@me", headers=headers) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        bot_username = data.get("username", "Unknown")
                        self.log_check("Discord API", True, f"Connected as {bot_username}")
                    else:
                        self.log_check("Discord API", False, f"HTTP {resp.status}")
                        
        except Exception as e:
            self.log_check("Discord API", False, f"Error: {str(e)}")
    
    async def check_twitch_api(self):
        """Check Twitch API accessibility."""
        try:
            client_id = os.getenv("TWITCH_CLIENT_ID")
            client_secret = os.getenv("TWITCH_CLIENT_SECRET")
            
            if not client_id or not client_secret:
                self.log_check("Twitch API", False, "Twitch credentials not set")
                return
            
            # Get OAuth token
            async with aiohttp.ClientSession() as session:
                token_data = {
                    "client_id": client_id,
                    "client_secret": client_secret,
                    "grant_type": "client_credentials"
                }
                
                async with session.post("https://id.twitch.tv/oauth2/token", data=token_data) as resp:
                    if resp.status == 200:
                        token_response = await resp.json()
                        access_token = token_response["access_token"]
                        
                        # Test API call
                        headers = {
                            "Client-ID": client_id,
                            "Authorization": f"Bearer {access_token}"
                        }
                        
                        async with session.get("https://api.twitch.tv/helix/users", headers=headers) as api_resp:
                            if api_resp.status == 200:
                                self.log_check("Twitch API", True, "Authentication successful")
                            else:
                                self.log_check("Twitch API", False, f"API call failed: HTTP {api_resp.status}")
                    else:
                        self.log_check("Twitch API", False, f"Authentication failed: HTTP {resp.status}")
                        
        except Exception as e:
            self.log_check("Twitch API", False, f"Error: {str(e)}")
    
    async def check_file_permissions(self):
        """Check file system permissions."""
        try:
            # Check if logs directory exists and is writable
            logs_dir = Path("logs")
            if not logs_dir.exists():
                logs_dir.mkdir(exist_ok=True)
            
            # Test writing to logs directory
            test_file = logs_dir / "health_check.tmp"
            test_file.write_text("health check test")
            test_file.unlink()
            
            self.log_check("File Permissions", True, "Logs directory writable")
            
        except Exception as e:
            self.log_check("File Permissions", False, f"Error: {str(e)}")
    
    async def check_network_connectivity(self):
        """Check basic network connectivity."""
        try:
            async with aiohttp.ClientSession() as session:
                # Test Discord connectivity
                async with session.get("https://discord.com", timeout=10) as resp:
                    discord_ok = resp.status == 200
                
                # Test Twitch connectivity  
                async with session.get("https://twitch.tv", timeout=10) as resp:
                    twitch_ok = resp.status == 200
                
                if discord_ok and twitch_ok:
                    self.log_check("Network Connectivity", True, "Discord and Twitch accessible")
                elif discord_ok:
                    self.log_check("Network Connectivity", False, "Twitch not accessible")
                elif twitch_ok:
                    self.log_check("Network Connectivity", False, "Discord not accessible")
                else:
                    self.log_check("Network Connectivity", False, "Neither Discord nor Twitch accessible")
                    
        except Exception as e:
            self.log_check("Network Connectivity", False, f"Error: {str(e)}")
    
    async def run_all_checks(self):
        """Run all health checks."""
        print("🔍 ValhallaBot2 Health Check")
        print("=" * 50)
        
        await self.check_environment_variables()
        await self.check_network_connectivity()
        await self.check_database_connection()
        await self.check_discord_api()
        await self.check_twitch_api()
        await self.check_file_permissions()
        
        print("\n" + "=" * 50)
        
        if self.overall_status:
            print("🎉 Overall Status: HEALTHY")
            return 0
        else:
            print("⚠️  Overall Status: UNHEALTHY")
            return 1
    
    def save_results(self, filename="health_check_results.json"):
        """Save results to a JSON file."""
        results_data = {
            "timestamp": datetime.utcnow().isoformat(),
            "overall_status": "HEALTHY" if self.overall_status else "UNHEALTHY",
            "checks": self.results
        }
        
        with open(filename, "w") as f:
            json.dump(results_data, f, indent=2)
        
        print(f"📄 Results saved to {filename}")

async def main():
    """Main function to run health checks."""
    # Load environment variables from .env file if it exists
    if Path(".env").exists():
        with open(".env") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    key, value = line.split("=", 1)
                    os.environ[key.strip()] = value.strip()
    
    checker = HealthChecker()
    exit_code = await checker.run_all_checks()
    
    # Save results for monitoring systems
    checker.save_results()
    
    sys.exit(exit_code)

if __name__ == "__main__":
    asyncio.run(main())
