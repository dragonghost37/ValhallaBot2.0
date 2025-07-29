
import asyncpg
import logging
from contextlib import asynccontextmanager

logger = logging.getLogger(__name__)

database_url = None
pool = None

async def init_pool():
    global pool
    if pool is None:
        if not database_url:
            raise RuntimeError("Database URL is not set in db_manager.database_url")
        pool = await asyncpg.create_pool(dsn=database_url, min_size=1, max_size=5)
        logger.info("✅ Database connection pool initialized")
    return pool

async def get_connection():
    global pool
    if pool is None:
        await init_pool()
    return await pool.acquire()

@asynccontextmanager
async def acquire():
    """Async context manager for acquiring a connection from the pool."""
    global pool
    if pool is None:
        await init_pool()
    conn = await pool.acquire()
    try:
        yield conn
    finally:
        await pool.release(conn)

async def release_connection(conn):
    global pool
    if pool:
        await pool.release(conn)

async def close_pool():
    global pool
    if pool:
        await pool.close()
        pool = None
        logger.info("✅ Database pool closed")
