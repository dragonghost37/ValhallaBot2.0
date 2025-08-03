#!/usr/bin/env python3

import discord
from discord.ext import commands, tasks
from discord import app_commands, Embed
import psycopg
import asyncio
import os
import aiohttp
from aiohttp import web
import json
from twitchio.ext import commands as twitch_commands
from datetime import datetime, timezone
import logging
import sys
import time
import uuid
import signal
from typing import Optional, Any, Dict, Set, Deque, DefaultDict, List, Tuple
from collections import defaultdict, deque


# ---- LOGGING SETUP ---- #
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)  # Only stdout for Render
    ]
)
logger = logging.getLogger(__name__)

# ---- CONFIGURATION ---- #
DISCORD_BOT_TOKEN = os.getenv("DISCORD_BOT_TOKEN")
TWITCH_CLIENT_ID = os.getenv("TWITCH_CLIENT_ID")
TWITCH_CLIENT_SECRET = os.getenv("TWITCH_CLIENT_SECRET")
TWITCH_BOT_TOKEN = os.getenv("TWITCH_BOT_TOKEN")
WEBHOOK_URL = os.getenv("WEBHOOK_URL")
EVENTSUB_SECRET = os.getenv("EVENTSUB_SECRET", "valhalla_secret")
POSTGRES_URL = os.getenv("DATABASE_URL")

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

# Global lock to prevent concurrent Twitch API calls
twitch_api_lock = asyncio.Lock()



# Global variables
twitch_token = None
currently_live = set()
stream_chat_counts = {}
twitch_to_discord = {}
stream_raids = {}  # {twitch_username: [ (raider, viewers, points_awarded) ]}
stream_raids_sent = {}  # Track raids sent by streamers
last_live_set = set()

# Global TwitchBot instance
twitch_bot = None

# ---- WEBHOOK SERVER SETUP ---- #
async def setup_webhook_server():
    """Setup the webhook server for Twitch EventSub"""
    app = web.Application()
    app.router.add_routes(routes)
    
    port = int(os.getenv("PORT", 10000))
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "0.0.0.0", port)
    await site.start()
    print(f"🌐 Webhook server started on port {port}")
    return runner

# ---- TWITCH AUTH ---- #
async def get_twitch_oauth_token():
    global twitch_token
    url = "https://id.twitch.tv/oauth2/token"
    params = {
        'client_id': TWITCH_CLIENT_ID,
        'client_secret': TWITCH_CLIENT_SECRET,
        'grant_type': 'client_credentials'
    }
    async with aiohttp.ClientSession() as session:
        async with session.post(url, data=params) as resp:
            data = await resp.json()
            twitch_token = data.get('access_token')

# ---- DATABASE INITIALIZATION ---- #
async def initialize_database():
    """Create database tables with simple schema"""
    async with await psycopg.AsyncConnection.connect(POSTGRES_URL) as conn:
        async with conn.cursor() as cur:
            await cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                discord_id TEXT PRIMARY KEY,
                twitch_username TEXT,
                rank TEXT DEFAULT 'Thrall',
                points INTEGER DEFAULT 0,
                referral_bonus_claimed BOOLEAN DEFAULT FALSE,
                referred_by TEXT
            )
            """)
            await cur.execute("""
            CREATE TABLE IF NOT EXISTS chats (
                chatter_id TEXT,
                streamer_id TEXT,
                count INTEGER DEFAULT 0,
                PRIMARY KEY (chatter_id, streamer_id)
            );
            """)
            await cur.execute("""
            CREATE TABLE IF NOT EXISTS raids (
                raider_id TEXT,
                target_id TEXT,
                viewers INTEGER,
                timestamp TIMESTAMP DEFAULT NOW()
            );
            """)
            await cur.execute("""
            CREATE TABLE IF NOT EXISTS chat_points (
                chatter_id TEXT,
                streamer_id TEXT,
                points_awarded INTEGER,
                timestamp TIMESTAMP DEFAULT NOW()
            );
            """)
            await conn.commit()
    print("✅ Database initialized successfully")

# ---- DATABASE HELPERS ---- #
async def get_user_by_discord_id(discord_id):
    """Get user by Discord ID"""
    async with await psycopg.AsyncConnection.connect(POSTGRES_URL) as conn:
        async with conn.cursor() as cur:
            await cur.execute("SELECT * FROM users WHERE discord_id = %s", (str(discord_id),))
            result = await cur.fetchone()
            if result:
                columns = [desc[0] for desc in cur.description]
                return dict(zip(columns, result))
            return None

async def get_user_by_twitch_username(twitch_username):
    """Get user by Twitch username"""
    async with await psycopg.AsyncConnection.connect(POSTGRES_URL) as conn:
        async with conn.cursor() as cur:
            await cur.execute("SELECT * FROM users WHERE twitch_username = %s", (twitch_username,))
            result = await cur.fetchone()
            if result:
                columns = [desc[0] for desc in cur.description]
                return dict(zip(columns, result))
            return None

async def create_user(discord_id, twitch_username=None, referred_by=None):
    """Create a new user"""
    async with await psycopg.AsyncConnection.connect(POSTGRES_URL) as conn:
        async with conn.cursor() as cur:
            await cur.execute(
                "INSERT INTO users (discord_id, twitch_username, referred_by) VALUES (%s, %s, %s) ON CONFLICT (discord_id) DO NOTHING",
                (str(discord_id), twitch_username, referred_by)
            )
            await conn.commit()

async def link_twitch_account(discord_id, twitch_username):
    """Link Twitch account to Discord user"""
    async with await psycopg.AsyncConnection.connect(POSTGRES_URL) as conn:
        async with conn.cursor() as cur:
            await cur.execute(
                "UPDATE users SET twitch_username = %s WHERE discord_id = %s",
                (twitch_username, str(discord_id))
            )
            await conn.commit()

async def update_user_points(discord_id=None, twitch_username=None, points_to_add=0):
    """Update user points by Discord ID or Twitch username"""
    async with await psycopg.AsyncConnection.connect(POSTGRES_URL) as conn:
        async with conn.cursor() as cur:
            if discord_id:
                await cur.execute(
                    "UPDATE users SET points = points + %s WHERE discord_id = %s",
                    (points_to_add, str(discord_id))
                )
            elif twitch_username:
                await cur.execute(
                    "UPDATE users SET points = points + %s WHERE twitch_username = %s",
                    (points_to_add, twitch_username)
                )
            await conn.commit()

async def get_user_rank(points):
    """Calculate rank based on points"""
    if points >= 500:
        return "Einherjar"
    elif points >= 200:
        return "Drengr" 
    elif points >= 75:
        return "Huscarl"
    elif points >= 25:
        return "Karl"
    else:
        return "Thrall"

async def update_user_rank(conn, discord_id):
    """Update user rank based on current points"""
    async with conn.cursor() as cur:
        await cur.execute("SELECT points FROM users WHERE discord_id = %s", (str(discord_id),))
        result = await cur.fetchone()
        if result:
            points = result[0]
            new_rank = await get_user_rank(points)
            await cur.execute(
                "UPDATE users SET rank = %s WHERE discord_id = %s",
                (new_rank, str(discord_id))
            )

async def record_chat_point(chatter_id, streamer_id, points_awarded):
    """Record chat points for analytics"""
    async with await psycopg.AsyncConnection.connect(POSTGRES_URL) as conn:
        async with conn.cursor() as cur:
            await cur.execute(
                "INSERT INTO chat_points (chatter_id, streamer_id, points_awarded) VALUES (%s, %s, %s)",
                (chatter_id, streamer_id, points_awarded)
            )
            await conn.commit()

async def record_raid(raider_id, target_id):
    """Record a raid for analytics"""
    async with await psycopg.AsyncConnection.connect(POSTGRES_URL) as conn:
        async with conn.cursor() as cur:
            await cur.execute(
                "INSERT INTO raids (raider_id, target_id) VALUES (%s, %s)",
                (raider_id, target_id)
            )
            await conn.commit()

async def claim_referral_bonus(discord_id):
    """Claim referral bonus and award points"""
    async with await psycopg.AsyncConnection.connect(POSTGRES_URL) as conn:
        async with conn.cursor() as cur:
            # Check if user exists and hasn't claimed bonus
            await cur.execute(
                "SELECT referral_bonus_claimed, referred_by FROM users WHERE discord_id = %s",
                (str(discord_id),)
            )
            result = await cur.fetchone()
            
            if result and not result[0] and result[1]:  # not claimed and has referrer
                # Award 10 points and mark as claimed
                await cur.execute(
                    "UPDATE users SET points = points + 10, referral_bonus_claimed = TRUE WHERE discord_id = %s",
                    (str(discord_id),)
                )
                
                # Award 5 points to referrer
                await cur.execute(
                    "UPDATE users SET points = points + 5 WHERE discord_id = %s",
                    (result[1],)
                )
                
                await conn.commit()
                return True
            return False

# ---- WEBHOOK ROUTES ---- #
@routes.post("/eventsub")
async def handle_eventsub(request):
    payload = await request.json()
    if "challenge" in payload:
        return web.Response(text=payload["challenge"])

    if payload.get("subscription", {}).get("type") == "channel.raid":
        event = payload["event"]
        raider = event["from_broadcaster_user_login"].lower()
        target = event["to_broadcaster_user_login"].lower()
        viewers = int(event["viewers"])

        logger.info(f"[EventSub] Received raid event: raider={raider}, target={target}, viewers={viewers}")
        # --- Log the raid for the stream summary (legacy, in-memory) ---
        target_lc = target.lower()
        if target_lc not in stream_raids:
            stream_raids[target_lc] = []
        stream_raids[target_lc].append((raider, viewers, 0))  # points_awarded is 0 by default
        logger.info(f"[EventSub] stream_raids[{target_lc}] now: {stream_raids[target_lc]}")

        try:
            async with await psycopg.AsyncConnection.connect(POSTGRES_URL) as conn:
                async with conn.cursor() as cur:
                    await cur.execute("SELECT discord_id FROM users WHERE twitch_username = %s", (raider,))
                    raider_row = await cur.fetchone()
                    await cur.execute("SELECT discord_id FROM users WHERE twitch_username = %s", (target,))
                    target_row = await cur.fetchone()
                    # Award points and record raid if both are linked
                    channel = discord.utils.get(bot.get_all_channels(), name="╡stream-summaries")
                    bot_commands_channel = discord.utils.get(bot.get_all_channels(), name="╡bot-commands")
                    # Use Discord display names if both are linked
                    raider_mention = f"`{raider}`"
                    target_mention = f"`{target}`"
                    if raider_row:
                        for guild in bot.guilds:
                            member = guild.get_member(int(raider_row[0]))
                            if member:
                                raider_mention = member.display_name
                                break
                    if target_row:
                        for guild in bot.guilds:
                            member = guild.get_member(int(target_row[0]))
                            if member:
                                target_mention = member.display_name
                                break
                    if raider_row and target_row:
                        try:
                            await cur.execute(
                                "INSERT INTO raids (raider_id, target_id, viewers) VALUES (%s, %s, %s)",
                                (raider_row[0], target_row[0], viewers)
                            )
                            await conn.commit()
                            logger.info(f"[EventSub] Raid recorded in DB: raider_id={raider_row[0]}, target_id={target_row[0]}, viewers={viewers}")
                            # Award points: 10 points per viewer
                            points_awarded = viewers * 10
                            await cur.execute(
                                "UPDATE users SET points = points + %s WHERE discord_id = %s",
                                (points_awarded, raider_row[0])
                            )
                            await conn.commit()
                            # Optionally update rank
                            await update_user_rank(conn, raider_row[0])
                            # Notify in stream-summaries
                            if channel:
                                await channel.send(f"⚔️ {raider_mention} raided {target_mention} with {viewers} viewer{'s' if viewers != 1 else ''}! 🏅 Awarded {points_awarded} points.")
                        except Exception as db_exc:
                            logger.error(f"[EventSub] Error recording raid in DB: {db_exc}")
                    elif raider_row and not target_row:
                        # Target not linked, send warning in bot-commands
                        if bot_commands_channel:
                            await bot_commands_channel.send(
                                f"{raider_mention} raided {target} with {viewers} viewer{'s' if viewers != 1 else ''} but was NOT awarded {viewers * 10} points since {target} is not a registered streamer in this Discord. "
                                f"Consider referring them here and earn 200 points once they reach 300 points!"
                            )
                        # Still post in stream-summaries for visibility
                        if channel:
                            await channel.send(f"⚔️ {raider_mention} raided `{target}` with {viewers} viewer{'s' if viewers != 1 else ''}!")
                    elif not raider_row and target_row:
                        # Raider not linked, send warning in bot-commands
                        if bot_commands_channel:
                            await bot_commands_channel.send(f"⚠️ Raid received from Twitch user `{raider}` to {target_mention} ({viewers} viewers), but raider is not linked to Discord. No points awarded.")
                        if channel:
                            await channel.send(f"⚔️ `{raider}` raided {target_mention} with {viewers} viewer{'s' if viewers != 1 else ''}!")
                    else:
                        # Neither linked, send warning in bot-commands
                        if bot_commands_channel:
                            await bot_commands_channel.send(f"⚠️ Raid received from Twitch user `{raider}` to Twitch user `{target}` ({viewers} viewers), but neither are linked to Discord. No points awarded.")
                        if channel:
                            await channel.send(f"⚔️ `{raider}` raided `{target}` with {viewers} viewer{'s' if viewers != 1 else ''}!")
        except Exception as exc:
            logger.error(f"[EventSub] Exception in raid handler: {exc}")
    return web.Response(text="OK")

@routes.get("/health")
async def health_check(request):
    """Health check endpoint for Render"""
    return web.Response(
        text="OK", 
        status=200,
        headers={"Content-Type": "text/plain"}
    )

@routes.get("/")
async def root_handler(request):
    """Root endpoint to show bot status"""
    try:
        async with await psycopg.AsyncConnection.connect(POSTGRES_URL) as conn:
            async with conn.cursor() as cur:
                await cur.execute("SELECT COUNT(*) FROM users")
                user_count = (await cur.fetchone())[0]
        status = {
            "status": "online",
            "bot_name": "ValhallaBot2",
            "users_registered": user_count,
            "discord_connected": bot.is_ready(),
            "timestamp": datetime.utcnow().isoformat()
        }
        return web.json_response(status)
    except Exception as e:
        return web.json_response(
            {"status": "error", "message": str(e)}, 
            status=500
        )

# ---- AWARD & RANK FUNCTIONS ---- #
async def award_chat_points(conn, chatter_discord_id, streamer_twitch_username, count=1):
    async with conn.cursor() as cur:
        logger.info(f"[award_chat_points] Called with chatter_discord_id={chatter_discord_id}, streamer_twitch_username={streamer_twitch_username}, count={count}")
        await cur.execute("SELECT discord_id, rank FROM users WHERE twitch_username = %s", (streamer_twitch_username,))
        streamer_row = await cur.fetchone()
        if not streamer_row:
            logger.warning(f"[award_chat_points] Streamer Twitch username '{streamer_twitch_username}' not found in users table.")
            return
        streamer_id = streamer_row[0]
        rank = streamer_row[1]
        points_per_message = rank_points.get(rank, 1)
        total_points = points_per_message * count

        logger.info(f"[award_chat_points] Streamer_id={streamer_id}, rank={rank}, points_per_message={points_per_message}, total_points={total_points}")

        # Calculate points awarded in last 48 hours
        await cur.execute("""
            SELECT COALESCE(SUM(points_awarded), 0)
            FROM chat_points
            WHERE chatter_id = %s AND streamer_id = %s AND timestamp > NOW() - INTERVAL '48 hours'
        """, (chatter_discord_id, streamer_id))
        recent_points = (await cur.fetchone())[0]
        logger.info(f"[award_chat_points] Recent points in last 48h: {recent_points}")

        if recent_points >= 100:
            logger.info(f"[award_chat_points] User {chatter_discord_id} already maxed out for streamer {streamer_id} in 48h window.")
            # Notify the user they have reached the max points for this streamer
            # Fetch Discord member objects
            chatter_member = None
            streamer_member = None
            streamer_display_name = streamer_twitch_username
            for guild in bot.guilds:
                chatter_member = guild.get_member(int(chatter_discord_id))
                streamer_member = guild.get_member(int(streamer_id))
                if streamer_member:
                    streamer_display_name = streamer_member.display_name
                if chatter_member:
                    break
            # If not found, try fetch_user
            if not streamer_member:
                try:
                    streamer_member = await bot.fetch_user(int(streamer_id))
                    streamer_display_name = streamer_member.display_name
                except Exception:
                    pass
            if not chatter_member:
                try:
                    chatter_member = await bot.fetch_user(int(chatter_discord_id))
                except Exception:
                    pass
            # Send public message to bot-commands channel
            channel = discord.utils.get(bot.get_all_channels(), name="╡bot-commands")
            message = (
                f"<@{chatter_discord_id}>, you have reached the max amount of points you can earn per 48hrs for chatting in {streamer_display_name}'s stream.\n"
                f"You are limited to only earning points for up to 100 chats per streamer per 48 hours.\n"
                f"Please go support other streamers in the community to continue earning points!"
            )
            if channel:
                try:
                    await channel.send(message)
                except Exception:
                    logger.warning(f"[award_chat_points] Could not send public message for user {chatter_discord_id}")
            return  # Already maxed out for this streamer in this window

        points_to_award = min(total_points, 100 - recent_points)
        logger.info(f"[award_chat_points] Calculated points_to_award={points_to_award}")
        if points_to_award <= 0:
            logger.info(f"[award_chat_points] No points to award for user {chatter_discord_id} in streamer {streamer_id} chat.")
            return

        await cur.execute("UPDATE users SET points = points + %s WHERE discord_id = %s", (points_to_award, chatter_discord_id))
        await update_user_rank(conn, chatter_discord_id)
        await cur.execute("""
            INSERT INTO chat_points (chatter_id, streamer_id, points_awarded, timestamp)
            VALUES (%s, %s, %s, NOW())
        """, (chatter_discord_id, streamer_id, points_to_award))
        logger.info(f"[award_chat_points] Awarded {points_to_award} points to user {chatter_discord_id} for chatting in streamer {streamer_id}'s stream.")
        # Check for referral bonus milestone
        await check_referral_bonus(conn, chatter_discord_id)

async def check_referral_bonus(conn, discord_id):
    """Check if user has reached 400 points and award referral bonus to their referrer"""
    async with conn.cursor() as cur:
        await cur.execute("SELECT points, referral_bonus_claimed, referred_by FROM users WHERE discord_id = %s", (discord_id,))
        user_data = await cur.fetchone()
        if not user_data:
            return
        points, referral_bonus_claimed, referred_by = user_data
        # Only proceed if user has a referrer
        if referred_by is None:
            return
        # Check if user has reached 400 points and hasn't claimed referral bonus yet
        if points >= 400 and not referral_bonus_claimed:
            # Mark bonus as claimed for this user
            await cur.execute("UPDATE users SET referral_bonus_claimed = TRUE WHERE discord_id = %s", (discord_id,))
            # Award 200 points to the referrer
            await cur.execute("UPDATE users SET points = points + 200 WHERE discord_id = %s", (referred_by,))
            await update_user_rank(conn, referred_by)
            # Notify in bot-commands channel
            channel = discord.utils.get(bot.get_all_channels(), name="╡bot-commands")
            if channel:
                try:
                    referrer_user = await bot.fetch_user(int(referred_by))
                    referred_user = await bot.fetch_user(int(discord_id))
                    await channel.send(
                        f"🎉 **Referral Bonus!** <@{referred_by}> earned 200 points because "
                        f"<@{discord_id}> reached 400 points! Thanks for growing our Valhalla community!"
                    )
                except Exception:
                    pass

async def update_user_rank(conn, discord_id):
    # Get all users sorted by points descending
    async with conn.cursor() as cur:
        await cur.execute("SELECT discord_id, points FROM users ORDER BY points DESC")
        users = await cur.fetchall()
        total_users = len(users)
        if total_users == 0:
            return

        # Find this user's position (1-based)
        user_points = None
        user_rank_index = None
        for idx, user in enumerate(users):
            if user[0] == str(discord_id):
                user_points = user[1]
                user_rank_index = idx + 1
                break
        if user_points is None:
            return

        await cur.execute("SELECT rank FROM users WHERE discord_id = %s", (discord_id,))
        old_rank_row = await cur.fetchone()
        old_rank = old_rank_row[0] if old_rank_row else "Thrall"

        # Calculate percentiles
        percentile = user_rank_index / total_users

        if percentile <= 0.05:
            new_rank = "Allfather"          # Top 5%
        elif percentile <= 0.15:
            new_rank = "Chieftain"          # Top 5–15%
        elif percentile <= 0.30:
            new_rank = "Jarl"               # Top 15–30%
        elif percentile <= 0.50:
            new_rank = "Berserker"          # Top 30–50%
        elif percentile <= 0.80:
            new_rank = "Raider"             # Top 50–80%
        else:
            new_rank = "Thrall"             # Bottom 20%

        if new_rank != old_rank:
            await cur.execute("UPDATE users SET rank = %s WHERE discord_id = %s", (new_rank, discord_id))
            # Notify in ╡bot-commands
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

import functools
# ---- EVENTSUB SUBSCRIPTION MANAGER ---- #
async def ensure_eventsub_subscriptions():
    """Background task to ensure EventSub subscriptions for all linked Twitch users."""
    global twitch_token
    try:
        # Get all linked Twitch usernames
        async with await psycopg.AsyncConnection.connect(POSTGRES_URL) as conn:
            async with conn.cursor() as cur:
                await cur.execute("SELECT twitch_username FROM users WHERE twitch_username IS NOT NULL")
                rows = await cur.fetchall()
                twitch_usernames = [row[0] for row in rows]

        # Get user IDs from Twitch API
        headers = {
            'Client-ID': TWITCH_CLIENT_ID,
            'Authorization': f'Bearer {twitch_token}'
        }
        user_ids = {}
        async with aiohttp.ClientSession() as session:
            for username in twitch_usernames:
                url = f"https://api.twitch.tv/helix/users?login={username}"
                async with session.get(url, headers=headers) as resp:
                    data = await resp.json()
                    if data.get("data"):
                        user_ids[username] = data["data"][0]["id"]

        # Get current EventSub subscriptions
        eventsub_url = "https://api.twitch.tv/helix/eventsub/subscriptions"
        async with aiohttp.ClientSession() as session:
            async with session.get(eventsub_url, headers=headers) as resp:
                subs_data = await resp.json()
                logger.info(f"[EventSub] Current subscriptions: {subs_data}")
                active_subs = set()
                for sub in subs_data.get("data", []):
                    cond = sub.get("condition", {})
                    # Suppress warning for missing broadcaster_user_id in channel.raid
                    if sub.get("type") == "channel.raid" and not cond.get("from_broadcaster_user_id"):
                        pass  # No warning needed
                    elif not cond.get("to_broadcaster_user_id"):
                        logger.warning(f"[EventSub] Subscription missing broadcaster_user_id: {sub}")
                    active_subs.add(cond.get("to_broadcaster_user_id"))

        # Create missing subscriptions
        for username, user_id in user_ids.items():
            if user_id not in active_subs:
                payload = {
                    "type": "channel.raid",
                    "version": "1",
                    "condition": {"to_broadcaster_user_id": user_id},
                    "transport": {
                        "method": "webhook",
                        "callback": WEBHOOK_URL + "/eventsub",
                        "secret": EVENTSUB_SECRET
                    }
                }
                async with aiohttp.ClientSession() as session:
                    try:
                        async with session.post(eventsub_url, headers=headers, json=payload) as resp:
                            if resp.status == 409:
                                logger.info(f"[EventSub] Subscription for {username} already exists (409 Conflict)")
                            elif resp.status != 202:
                                error = await resp.text()
                                logger.warning(f"[EventSub] Failed to create subscription for {username}: {error}")
                    except Exception as e:
                        logger.warning(f"[EventSub] Exception creating subscription for {username}: {e}")
    except Exception as exc:
        logger.error(f"[EventSub] Subscription manager error: {exc}")
    await asyncio.sleep(600)  # Run every 10 minutes
# ---- SLASH COMMANDS ---- #

# Ensure slash commands are synced on startup
@bot.event
async def on_ready():
    try:
        await bot.tree.sync()
        print(f"✅ Synced slash commands for {bot.user}")
    except Exception as e:
        print(f"Error syncing slash commands: {e}")

@bot.tree.command(name="linktwitch", description="Link your Discord to your Twitch account")
@app_commands.describe(twitch_username="Your Twitch username")
async def linktwitch_slash(interaction: discord.Interaction, twitch_username: str):
    if interaction.channel is None or interaction.channel.name != "╡valhallabot-link":
        await interaction.response.send_message(
            "❌ You can only use this command in the ╡valhallabot-link channel.",
            ephemeral=True
        )
        return
    discord_id = str(interaction.user.id)
    twitch_username = twitch_username.lower()

    # --- Validate Twitch username exists via Twitch API ---
    # Use client credentials flow token
    global twitch_token
    if not twitch_token:
        await get_twitch_oauth_token()
    headers = {
        'Client-ID': TWITCH_CLIENT_ID,
        'Authorization': f'Bearer {twitch_token}'
    }
    url = f"https://api.twitch.tv/helix/users?login={twitch_username}"
    async with aiohttp.ClientSession() as session:
        async with session.get(url, headers=headers) as resp:
            if resp.status != 200:
                await interaction.response.send_message(
                    f"❌ Could not validate Twitch username `{twitch_username}` (Twitch API error). Please try again later.",
                    ephemeral=True
                )
                return
            data = await resp.json()
            if not data.get("data"):
                await interaction.response.send_message(
                    f"❌ Twitch username `{twitch_username}` does not exist. Please check your spelling and try again.",
                    ephemeral=True
                )
                return

    async with await psycopg.AsyncConnection.connect(POSTGRES_URL) as conn:
        async with conn.cursor() as cur:
            # Check if user already exists and has Twitch linked
            await cur.execute("SELECT twitch_username, points FROM users WHERE discord_id = %s", (discord_id,))
            existing_user = await cur.fetchone()
            is_first_link = not existing_user or existing_user[0] is None
            # Award 100 points bonus for first-time Twitch linking
            bonus_points = 100 if is_first_link else 0
            await cur.execute(
                """
                INSERT INTO users (discord_id, twitch_username, rank, points)
                VALUES (%s, %s, 'Thrall', %s)
                ON CONFLICT (discord_id) DO UPDATE SET 
                    twitch_username = EXCLUDED.twitch_username,
                    points = CASE 
                        WHEN users.twitch_username IS NULL THEN users.points + EXCLUDED.points
                        ELSE users.points
                    END
                """,
                (discord_id, twitch_username, bonus_points)
            )
            # Update user rank after points change
            if is_first_link:
                await update_user_rank(conn, discord_id)
                await check_referral_bonus(conn, discord_id)
        twitch_to_discord[twitch_username] = discord_id

    # --- Ensure TwitchBot joins the new channel if running ---
    global twitch_bot
    if twitch_bot is not None:
        try:
            await twitch_bot.join_channels([twitch_username])
        except Exception as e:
            print(f"Error joining new Twitch channel {twitch_username}: {e}")

    # Always send a response to the user
    if is_first_link and bonus_points > 0:
        await interaction.response.send_message(
            f"✅ {interaction.user.mention}, your Twitch username `{twitch_username}` has been linked!\n"
            f"🎉 **Welcome Bonus**: You earned {bonus_points} points for linking your Twitch account!",
            ephemeral=True
        )
        # Post a public embed in #valhallabot-link
        channel = discord.utils.get(bot.get_all_channels(), name="╡valhallabot-link")
        if channel:
            embed = discord.Embed(
                title="Twitch Linked!",
                description=(
                    f"{interaction.user.mention} has linked their Twitch account: [`{twitch_username}`](https://twitch.tv/{twitch_username})!\n"
                    f"🎉 Welcome to Valhalla's Twitch integration! You earned **{bonus_points} points**."
                ),
                color=0x9146FF
            )
            embed.set_thumbnail(url=interaction.user.display_avatar.url)
            embed.timestamp = datetime.now(timezone.utc)
            await channel.send(embed=embed)
    else:
        await interaction.response.send_message(
            f"✅ {interaction.user.mention}, your Twitch username `{twitch_username}` has been updated!",
            ephemeral=True
        )

# ---- UNLINK TWITCH COMMAND ---- #
@bot.tree.command(name="unlinktwitch", description="Unlink your Twitch account from your Discord account")
async def unlinktwitch_slash(interaction: discord.Interaction):
    if interaction.channel is None or interaction.channel.name != "╡valhallabot-link":
        await interaction.response.send_message(
            "❌ You can only use this command in the ╡valhallabot-link channel.",
            ephemeral=True
        )
        return
    discord_id = str(interaction.user.id)
    async with await psycopg.AsyncConnection.connect(POSTGRES_URL) as conn:
        async with conn.cursor() as cur:
            # Check if user exists and has Twitch linked
            await cur.execute("SELECT twitch_username FROM users WHERE discord_id = %s", (discord_id,))
            row = await cur.fetchone()
            if not row or row[0] is None:
                await interaction.response.send_message(
                    "❌ You do not have a linked Twitch account to unlink.",
                    ephemeral=True
                )
                return
            twitch_username = row[0]
            await cur.execute(
                "UPDATE users SET twitch_username = NULL WHERE discord_id = %s",
                (discord_id,)
            )
            await conn.commit()
            # Remove from twitch_to_discord mapping if present
            if twitch_username in twitch_to_discord:
                del twitch_to_discord[twitch_username]
    # Optionally, have TwitchBot part the channel if running
    global twitch_bot
    if twitch_bot is not None:
        try:
            await twitch_bot.part_channels([twitch_username])
        except Exception as e:
            print(f"Error parting Twitch channel {twitch_username}: {e}")
    await interaction.response.send_message(
        f"✅ {interaction.user.mention}, your Twitch account `{twitch_username}` has been unlinked.",
        ephemeral=True
    )

@bot.tree.command(name="rank", description="Show your current Valhalla rank")
async def rank_slash(interaction: discord.Interaction):
    async with await psycopg.AsyncConnection.connect(POSTGRES_URL) as conn:
        async with conn.cursor() as cur:
            await cur.execute("SELECT rank FROM users WHERE discord_id = %s", (str(interaction.user.id),))
            row = await cur.fetchone()
    if row:
        rank = row[0]
        icon = rank_icons.get(rank, "")
        await interaction.response.send_message(f"🏅 {interaction.user.mention}, your current rank is {icon} **{rank}**.", ephemeral=True)
    else:
        await interaction.response.send_message("❌ You haven't linked your Twitch yet.", ephemeral=True)

@bot.tree.command(name="mypoints", description="Show your current points and rank")
async def mypoints_slash(interaction: discord.Interaction):
    async with await psycopg.AsyncConnection.connect(POSTGRES_URL) as conn:
        async with conn.cursor() as cur:
            await cur.execute("SELECT points, rank FROM users WHERE discord_id = %s", (str(interaction.user.id),))
            row = await cur.fetchone()
    if row:
        points = row[0]
        rank = row[1]
        await interaction.response.send_message(f"💰 {interaction.user.mention}, you have **{points}** points and your rank is **{rank}**.", ephemeral=True)
    else:
        await interaction.response.send_message("❌ You haven't linked your Twitch yet.", ephemeral=True)

@bot.tree.command(name="leaderboard", description="Show the top 50 warriors")
async def leaderboard_slash(interaction: discord.Interaction):
    async with await psycopg.AsyncConnection.connect(POSTGRES_URL) as conn:
        async with conn.cursor() as cur:
            await cur.execute("SELECT discord_id, rank, points FROM users ORDER BY points DESC LIMIT 50")
            rows = await cur.fetchall()
    if not rows:
        await interaction.response.send_message("📉 No leaderboard data yet.", ephemeral=True)
        return
    msg = "🏆 Valhalla's Mightiest Warriors 🏆\n"
    for i, row in enumerate(rows, 1):
        discord_id = row[0]
        rank = row[1]
        points = row[2]
        name = f"User({discord_id})"
        for guild in bot.guilds:
            member = guild.get_member(int(discord_id))
            if member:
                name = member.display_name
                break
        icon = rank_icons.get(rank, "")
        msg += f"{i}. {icon} {name} | {rank} | {points} pts\n"
    await interaction.response.send_message(msg, ephemeral=True)

@bot.tree.command(name="stats", description="Show your Valhalla Warrior stats")
async def stats_slash(interaction: discord.Interaction):
    discord_id = str(interaction.user.id)
    async with await psycopg.AsyncConnection.connect(POSTGRES_URL) as conn:
        async with conn.cursor() as cur:
            await cur.execute("SELECT rank FROM users WHERE discord_id = %s", (discord_id,))
            row = await cur.fetchone()
            rank = row[0] if row else "Thrall"
            color = rank_colors.get(rank, 0x7289DA)

            # Top 3 members you support
            await cur.execute("""
                SELECT streamer_id, count FROM chats
                WHERE chatter_id = %s
                ORDER BY count DESC
                LIMIT 3
            """, (discord_id,))
            rows = await cur.fetchall()
            support_list = []
            for row in rows:
                streamer_id = row[0]
                count = row[1]
                name = f"User({streamer_id})"
                for guild in bot.guilds:
                    member = guild.get_member(int(streamer_id))
                    if member:
                        name = member.display_name
                        break
                support_list.append(f"{name} ({count} chats)")

            # Top 3 members supporting you
            await cur.execute("""
                SELECT chatter_id, count FROM chats
                WHERE streamer_id = %s
                ORDER BY count DESC
                LIMIT 3
            """, (discord_id,))
            rows = await cur.fetchall()
            supporter_list = []
            for row in rows:
                chatter_id = row[0]
                count = row[1]
                name = f"User({chatter_id})"
                for guild in bot.guilds:
                    member = guild.get_member(int(chatter_id))
                    if member:
                        name = member.display_name
                        break
                supporter_list.append(f"{name} ({count} chats)")

    embed = discord.Embed(
        title=f"{interaction.user.display_name}'s Valhalla Warrior Stats",
        color=color,
        description="Here's a summary of your Valhalla Warrior stats:"
    )
    embed.add_field(
        name="Top 3 Members You Support",
        value="\n".join(support_list) if support_list else "No data.",
        inline=False
    )
    embed.add_field(
        name="Top 3 Members Supporting You",
        value="\n".join(supporter_list) if supporter_list else "No data.",
        inline=False
    )
    
    embed.timestamp = datetime.now(timezone.utc)
    await interaction.response.send_message(embed=embed, ephemeral=True)

@bot.tree.command(name="help", description="Show all ValhallaBot commands")
async def help_slash(interaction: discord.Interaction):
    embed = discord.Embed(
        title="ValhallaBot Command Picker",
        description="Here are the available commands:",
        color=0x7289DA
    )
    embed.add_field(name="/linktwitch <twitch_username>", value="Link your Discord to your Twitch account.", inline=False)
    embed.add_field(name="/unlinktwitch", value="Unlink your Twitch account from your Discord account.", inline=False)
    embed.add_field(name="/refer <@user>", value="Refer someone who just joined the server (earn 200 pts when they reach 400 pts).", inline=False)
    embed.add_field(name="/rank", value="Show your current Valhalla rank.", inline=False)
    embed.add_field(name="/mypoints", value="Show your current points and rank.", inline=False)
    embed.add_field(name="/leaderboard", value="Show top 50 warriors.", inline=False)
    embed.add_field(name="/stats", value="Show your Valhalla Warrior stats.", inline=False)
    await interaction.response.send_message(embed=embed, ephemeral=True)

@bot.tree.command(name="howtouse", description="Show how to use ValhallaBot")
async def how_to_use_slash(interaction: discord.Interaction):
    embed = discord.Embed(
        title="⚔️ HOW TO USE VALHALLABOT",
        description="Your path to glory in the Valhalla Gaming Discord",
        color=0xFFD700
    )

    embed.add_field(
        name="🧩 Step 1: Link Your Twitch",
        value="Use `/linktwitch <your_twitch_username>` to connect your Discord and Twitch.\n> Example: `/linktwitch odinstreams`\n> 🎁 **Bonus**: Get 100 points for your first link!",
        inline=False
    )

    embed.add_field(
        name="🗡️ Step 2: Earn Points",
        value="• 💬 Chat in Valhalla streams (up to 100 pts/streamer every 48h)\n"
              "• ⚔️ Raid Valhalla members (10 pts per viewer, up to 5x/month per target)\n"
              "• 🤝 Refer new members (200 pts when they reach 400 pts)",
        inline=False
    )

    embed.add_field(
        name="📈 Step 3: Climb the Ranks",
        value="Ranks auto-update based on your percentile:\n"
              "• 🦾 Allfather – Top 5%\n"
              "• 🛡️ Chieftain – 5–15%\n"
              "• 🦅 Jarl – 15–30%\n"
              "• 🐺 Berserker – 30–50%\n"
              "• 🛶 Raider – 50–80%\n"
              "• 🪓 Thrall – Bottom 20%",
        inline=False
    )

    embed.add_field(
        name="🔍 Commands",
        value="• `/linktwitch` – Connect your Twitch (100 pt bonus!)\n"
              "• `/refer @user` – Refer new members (200 pt bonus!)\n"
              "• `/rank` – Show your rank\n"
              "• `/mypoints` – View your points\n"
              "• `/leaderboard` – Top 50 warriors\n"
              "• `/stats` – See your support stats\n"
              "• `/help` – Full command list",
        inline=False
    )

    embed.add_field(
        name="📣 Going Live?",
        value="ValhallaBot will post in **#now-live** when you stream — game, viewers, rank, and link!",
        inline=False
    )

    embed.set_footer(text="🛡️ Fight. Raid. Rank up. Valhalla is watching.")
    embed.timestamp = datetime.utcnow()

    await interaction.response.send_message(embed=embed, ephemeral=True)

@bot.tree.command(name="refer", description="Refer someone who just joined the server")
@app_commands.describe(user="The Discord user you referred to this server")
async def refer_slash(interaction: discord.Interaction, user: discord.Member):
    # Make sure the command is used in the right channel
    if interaction.channel is None or interaction.channel.name != "╡valhallabot-link":
        await interaction.response.send_message(
            "❌ You can only use this command in the ╡valhallabot-link channel.",
            ephemeral=True
        )
        return
    
    referrer_id = str(interaction.user.id)
    referred_id = str(user.id)
    
    # Can't refer yourself
    if referrer_id == referred_id:
        await interaction.response.send_message("❌ You can't refer yourself!", ephemeral=True)
        return
    
    conn = await psycopg.AsyncConnection.connect(POSTGRES_URL)
    
    # Check if referrer exists and has linked Twitch
    referrer_data = await conn.fetchrow("SELECT twitch_username FROM users WHERE discord_id = $1", referrer_id)
    if not referrer_data or not referrer_data["twitch_username"]:
        await conn.close()
        await interaction.response.send_message("❌ You must link your Twitch account first before referring others!", ephemeral=True)
        return
    
    # Check if referred user already exists
    referred_data = await conn.fetchrow("SELECT referred_by FROM users WHERE discord_id = $1", referred_id)
    if referred_data:
        if referred_data["referred_by"]:
            await conn.close()
            await interaction.response.send_message(f"❌ {user.mention} was already referred by someone else!", ephemeral=True)
            return
        else:
            # User exists but has no referrer, set the referrer
            await conn.execute("UPDATE users SET referred_by = $1 WHERE discord_id = $2", referrer_id, referred_id)
    else:
        # Create new user entry with referrer
        await conn.execute(
            "INSERT INTO users (discord_id, rank, points, referred_by) VALUES ($1, 'Thrall', 0, $2)",
            referred_id, referrer_id
        )
    
    await conn.close()
    
    await interaction.response.send_message(
        f"✅ {interaction.user.mention} has referred {user.mention}! 🎉\n"
        f"When {user.mention} reaches 400 points, you'll earn a 200 point referral bonus!",
        ephemeral=False
    )

# ---- TWITCH BOT ---- #
class TwitchBot(twitch_commands.Bot):
    def __init__(self, chat_counts, user_map, channels):
        super().__init__(
            token=TWITCH_BOT_TOKEN,
            prefix="!",
            initial_channels=[]
        )
        self.chat_counts = chat_counts
        self.user_map = user_map
        self.channels_to_join = channels

    async def event_ready(self):
        print(f"TwitchBot connected as {self.nick}")
        try:
            await self.join_channels(self.channels_to_join)
        except Exception as e:
            logging.exception("Error joining Twitch channels:")

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
            logger.info(f"[TwitchBot] Chat event: chatter={chatter} (discord_id={discord_chatter}), streamer={streamer} (discord_id={discord_streamer}), count={self.chat_counts[streamer][discord_chatter]}")
            await log_chat(discord_chatter, discord_streamer)
            # Award chat points based on streamer's rank
            try:
                async with await psycopg.AsyncConnection.connect(POSTGRES_URL) as conn:
                    await award_chat_points(conn, discord_chatter, streamer, count=1)
            except Exception as e:
                logger.error(f"[TwitchBot] Error awarding chat points: {e}")

async def log_chat(chatter_discord_id, streamer_discord_id):
    async with await psycopg.AsyncConnection.connect(POSTGRES_URL) as conn:
        async with conn.cursor() as cur:
            await cur.execute(
                """
                INSERT INTO chats (chatter_id, streamer_id, count)
                VALUES (%s, %s, 1)
                ON CONFLICT (chatter_id, streamer_id) DO UPDATE SET count = chats.count + 1
                """,
                (chatter_discord_id, streamer_discord_id)
            )
            await conn.commit()
    logger.info(f"[log_chat] Updated chats: chatter_id={chatter_discord_id}, streamer_id={streamer_discord_id}")

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

    conn = await psycopg.AsyncConnection.connect(POSTGRES_URL)
    async with conn.cursor() as cur:
        await cur.execute("SELECT discord_id, twitch_username FROM users WHERE twitch_username IS NOT NULL")
        users = await cur.fetchall()
        for user in users:
            twitch_username = user[1]
            twitch_to_discord[twitch_username] = user[0]

    async with twitch_api_lock:
        async with aiohttp.ClientSession() as session:
            headers = {
                'Client-ID': TWITCH_CLIENT_ID,
                'Authorization': f'Bearer {twitch_token}'
            }
            for user in users:
                twitch_username = user[1]
                url = f"https://api.twitch.tv/helix/streams?user_login={twitch_username}"
                try:
                    async with session.get(url, headers=headers) as resp:
                        if resp.status == 401:
                            # Token expired, refresh and retry once
                            print("Twitch token expired, refreshing...")
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
                                print("Failed to refresh Twitch token.")
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
                    print(f"Error checking stream status for {twitch_username}: {e}")

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

            async with conn.cursor() as cur2:
                await cur2.execute("SELECT rank FROM users WHERE discord_id = %s", (str(discord_id),))
                row = await cur2.fetchone()
                rank = row[0] if row else "Unknown"

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

            # Always post a new embed for each user going live
            await channel.send(embed=embed)

    # Handle ended streams
    ended_streams = currently_live - live_now
    for twitch_username in ended_streams:
        discord_id = twitch_to_discord.get(twitch_username)
        chatters = stream_chat_counts.get(twitch_username, {})
        total_chats = sum(chatters.values())
        channel = discord.utils.get(bot.get_all_channels(), name="╡stream-summaries")
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
            async with conn.cursor() as cur3:
                await cur3.execute("SELECT rank FROM users WHERE discord_id = %s", (str(discord_id),))
                row = await cur3.fetchone()
                if row:
                    rank = row[0]
            
            color = rank_colors.get(rank, 0x7289DA)

            # Handle raids sent - post points awarded messages
            raids_sent = stream_raids_sent.pop(twitch_username, [])
            for target, viewers, points in raids_sent:
                target_id = twitch_to_discord.get(target)
                # Get display names for streamer and target
                streamer_name = twitch_username
                target_name = target
                for guild in bot.guilds:
                    member = guild.get_member(int(discord_id))
                    if member:
                        streamer_name = member.display_name
                        break
                if target_id:
                    for guild in bot.guilds:
                        member = guild.get_member(int(target_id))
                        if member:
                            target_name = member.display_name
                            break
                streamer_url = f"https://twitch.tv/{twitch_username}"
                target_url = f"https://twitch.tv/{target}"
                if channel:
                    if points == 0:
                        await channel.send(
                            f"⚠️ {streamer_name} raided {target_name} with {viewers} viewers, but no points were awarded because the target is not linked.\n"
                            f"🔗 [{streamer_name}]({streamer_url}) → [{target}]({target_url})"
                        )
                    else:
                        await channel.send(
                            f"⚔️ {streamer_name} raided {target_name} with {viewers} viewers!\n"
                            f"{streamer_name} earned **{points} points** for this raid.\n"
                            f"🔗 [{streamer_name}]({streamer_url}) → [{target_name}]({target_url})"
                        )

            # Build stream summary embed
            embed = discord.Embed(
                title=f"{streamer_name}'s Stream Summary",
                color=color,
                description=f"Here's a summary of your Valhalla Warrior support:"
            )
            # Chatters
            if chatters:
                chatter_names = []
                for chatter_id in chatters.keys():
                    name = f"User({chatter_id})"
                    for guild in bot.guilds:
                        member = guild.get_member(int(chatter_id))
                        if member:
                            name = member.display_name
                            break
                    chatter_names.append(name)
                embed.add_field(
                    name="Chatters",
                    value=f"You received {total_chats} chats from Valhalla Warriors\n" + ", ".join(chatter_names),
                    inline=False
                )
            else:
                embed.add_field(name="Chatters", value="No chatters this stream.", inline=False)

            # Raids Received
            async with conn.cursor() as cur:
                await cur.execute(
                    "SELECT raider_id, viewers, timestamp FROM raids WHERE target_id = %s AND timestamp > NOW() - INTERVAL '24 hours'",
                    (str(discord_id),)
                )
                db_raids = await cur.fetchall()
            if db_raids:
                total_raids = len(db_raids)
                total_raid_viewers = sum(r[1] if len(r) > 1 and isinstance(r[1], int) else 0 for r in db_raids)
                raider_names = []
                for r in db_raids:
                    raider_id = r[0]
                    # Always map broadcaster to broadcaster (Discord ID to display name)
                    name = f"User({raider_id})"
                    for guild in bot.guilds:
                        member = guild.get_member(int(raider_id))
                        if member:
                            name = member.display_name
                            break
                    raider_names.append(name)
                embed.add_field(
                    name="Raids",
                    value=f"You received {total_raids} raid{'s' if total_raids > 1 else ''} with {total_raid_viewers} viewer{'s' if total_raid_viewers != 1 else ''}\n" + ", ".join(raider_names),
                    inline=False
                )
            else:
                embed.add_field(name="Raids", value="No raids this stream.", inline=False)

            # Raids Sent
            async with conn.cursor() as cur:
                await cur.execute(
                    "SELECT target_id, viewers, timestamp FROM raids WHERE raider_id = %s AND timestamp > NOW() - INTERVAL '24 hours'",
                    (str(discord_id),)
                )
                db_raids_sent = await cur.fetchall()
            if db_raids_sent:
                total_sent = len(db_raids_sent)
                total_sent_viewers = sum(r[1] if len(r) > 1 and isinstance(r[1], int) else 0 for r in db_raids_sent)
                target_names = []
                for r in db_raids_sent:
                    target_id = r[0]
                    # Always map broadcaster to broadcaster (Discord ID to display name)
                    name = f"User({target_id})"
                    for guild in bot.guilds:
                        member = guild.get_member(int(target_id))
                        if member:
                            name = member.display_name
                            break
                    target_names.append(name)
                embed.add_field(
                    name="Raids Sent",
                    value=f"You sent {total_sent} raid{'s' if total_sent > 1 else ''} with {total_sent_viewers} viewer{'s' if total_sent_viewers != 1 else ''}\n" + ", ".join(target_names),
                    inline=False
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
            # Query the raids table for raids received during this stream session
            async with conn.cursor() as cur:
                # Get stream start and end times (approximate: last time user went live to now)
                # For simplicity, use last 24 hours as the stream window
                await cur.execute(
                    "SELECT raider_id, viewers, timestamp FROM raids WHERE target_id = %s AND timestamp > NOW() - INTERVAL '24 hours'",
                    (str(discord_id),)
                )
                db_raids = await cur.fetchall()
            if db_raids:
                total_raids = len(db_raids)
                total_raid_viewers = sum(r[1] if len(r) > 1 and isinstance(r[1], int) else 0 for r in db_raids)
                raider_mentions = " ".join(
                    f"<@{r[0]}>" if r[0] else "Unknown"
                    for r in db_raids
                )
                embed.add_field(
                    name="Raids",
                    value=f"You received {total_raids} raid{'s' if total_raids > 1 else ''} with {total_raid_viewers} viewer{'s' if total_raid_viewers != 1 else ''}\n{raider_mentions}",
                    inline=False
                )
            else:
                embed.add_field(name="Raids", value="No raids this stream.", inline=False)

            # Raids Sent (summary only, now from DB)
            async with conn.cursor() as cur:
                await cur.execute(
                    "SELECT target_id, viewers, timestamp FROM raids WHERE raider_id = %s AND timestamp > NOW() - INTERVAL '24 hours'",
                    (str(discord_id),)
                )
                db_raids_sent = await cur.fetchall()
            if db_raids_sent:
                total_sent = len(db_raids_sent)
                total_sent_viewers = sum(r[1] if len(r) > 1 and isinstance(r[1], int) else 0 for r in db_raids_sent)
                target_mentions = " ".join(
                    f"<@{r[0]}>" if r[0] else "Unknown"
                    for r in db_raids_sent
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

            # Award chat points and update ranks for all users who chatted during the stream
            logger.info(f"[StreamEnd] Awarding chat points and updating ranks for streamer '{twitch_username}' (discord_id={discord_id})")
            async with conn.cursor() as cur_award:
                await cur_award.execute("SELECT chatter_id, count FROM chats WHERE streamer_id = %s", (str(discord_id),))
                all_chatters = await cur_award.fetchall()
                for chatter_row in all_chatters:
                    chatter_id = chatter_row[0]
                    count = chatter_row[1]
                    logger.info(f"[StreamEnd] Awarding chat points: chatter_id={chatter_id}, streamer_twitch_username={twitch_username}, count={count}")
                    await award_chat_points(conn, chatter_id, twitch_username, count)
                    # Always update rank after awarding points
                    await update_user_rank(conn, chatter_id)

        stream_chat_counts.pop(twitch_username, None)
    
    await conn.close()
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
    stream_info = {}

    conn = await psycopg.AsyncConnection.connect(POSTGRES_URL)
    async with conn.cursor() as cur:
        await cur.execute("SELECT discord_id, twitch_username, rank FROM users WHERE twitch_username IS NOT NULL")
        users = await cur.fetchall()
        for user in users:
            discord_id = user[0]
            twitch_username = user[1]
            rank = user[2]
            twitch_to_discord[twitch_username] = discord_id
            live_by_rank.setdefault(rank, []).append((discord_id, twitch_username))

    async with twitch_api_lock:
        async with aiohttp.ClientSession() as session:
            headers = {
                'Client-ID': TWITCH_CLIENT_ID,
                'Authorization': f'Bearer {twitch_token}'
            }
            for user in users:
                twitch_username = user[1]
                url = f"https://api.twitch.tv/helix/streams?user_login={twitch_username}"
                try:
                    async with session.get(url, headers=headers) as resp:
                        data = await resp.json()
                        if data.get('data'):
                            stream = data['data'][0]
                            current_live_set.add(twitch_username)
                            stream_info[twitch_username] = {
                                'game_name': stream.get('game_name', 'Unknown'),
                                'title': stream.get('title', ''),
                                'viewer_count': stream.get('viewer_count', 0),
                                'started_at': stream.get('started_at', '')
                            }
                except Exception as e:
                    print(f"Error checking stream status for {twitch_username}: {e}")

    await conn.close()

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

            # Send new embeds, but only for ranks with at least one currently live stream
            for rank, icon, pts, desc in rank_order:
                # Filter only those in this rank who are currently live
                live_streamers = [
                    (discord_id, twitch_username)
                    for discord_id, twitch_username in live_by_rank.get(rank, [])
                    if twitch_username in current_live_set and twitch_username in stream_info
                ]
                if not live_streamers:
                    continue  # Skip this rank if no one is live

                color = rank_colors.get(rank, 0x7289DA)
                embed = Embed(
                    title=f"{icon} Currently Live {rank} Channels",
                    description=f"{desc}\n",
                    color=color
                )
                embed.set_footer(text=f"Last Updated • {datetime.now(timezone.utc).strftime('%b %d, %Y at %I:%M %p UTC')}")


                for discord_id, twitch_username in live_streamers:
                    stream = stream_info.get(twitch_username)
                    if not stream:
                        continue
                    game = stream.get("game_name", "Unknown")
                    viewers = stream.get("viewer_count", "?")
                    started_at = stream.get("started_at")

                    # Try to get the display name from the guilds
                    display_name = None
                    for guild in bot.guilds:
                        member = guild.get_member(int(discord_id))
                        if member:
                            display_name = member.display_name
                            break
                    if not display_name:
                        display_name = str(discord_id)

                    try:
                        start_dt = datetime.fromisoformat(started_at.replace("Z", "+00:00"))
                        now = datetime.now(timezone.utc)
                        duration = now - start_dt
                        hours, remainder = divmod(int(duration.total_seconds()), 3600)
                        minutes = remainder // 60
                        duration_str = f"{hours}h {minutes}m" if hours > 0 else f"{minutes}m"
                    except Exception as e:
                        print(f"Error parsing stream start time for {twitch_username}: {e}")
                        duration_str = "?"

                    embed.add_field(
                        name=f"{display_name}",
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

# ---- MAIN FUNCTION ---- #
async def main():
    """Main startup function for Render deployment"""
    global twitch_token

    print("🛡️ Starting ValhallaBot2 on Render...")

    # Initialize database
    await initialize_database()

    # Get Twitch token
    await get_twitch_oauth_token()

    # Setup webhook server
    webhook_runner = await setup_webhook_server()

    # --- Start TwitchBot with all linked channels ---
    global twitch_bot
    # Gather all linked Twitch usernames
    async with await psycopg.AsyncConnection.connect(POSTGRES_URL) as conn:
        async with conn.cursor() as cur:
            await cur.execute("SELECT twitch_username, discord_id FROM users WHERE twitch_username IS NOT NULL")
            rows = await cur.fetchall()
            twitch_usernames = [row[0] for row in rows]
            user_map = {row[0]: row[1] for row in rows}

    twitch_bot = TwitchBot(chat_counts=stream_chat_counts, user_map=user_map, channels=twitch_usernames)
    # Start TwitchBot in the background
    loop = asyncio.get_running_loop()
    twitch_task = loop.create_task(twitch_bot.start())

    # Start background tasks
    if not check_live_streams.is_running():
        check_live_streams.start()
    if not auto_post_currently_live.is_running():
        auto_post_currently_live.start()

    # Start EventSub subscription manager as a background task
    loop = asyncio.get_running_loop()
    loop.create_task(ensure_eventsub_subscriptions())

    # Start Discord bot
    try:
        await bot.start(DISCORD_BOT_TOKEN)
    except Exception as e:
        print(f"Error starting bot: {e}")
        raise
    finally:
        # Cleanup webhook server
        if 'webhook_runner' in locals():
            await webhook_runner.cleanup()

# ---- PROGRAM ENTRY POINT ---- #
if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("Bot stopped by user")
    except Exception as e:
        print(f"Fatal error: {e}")
        import traceback
        traceback.print_exc()
