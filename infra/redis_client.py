import redis
import os
import logging

logger = logging.getLogger(__name__)

# Redis 설정 환경 변수에서 가져오기
REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT = int(os.getenv("REDIS_PORT", 6379))
REDIS_DB = int(os.getenv("REDIS_DB", 0))

try:
    redis_client = redis.Redis(
        host=REDIS_HOST,
        port=REDIS_PORT,
        db=REDIS_DB,
        decode_responses=True
    )
    redis_client.ping()
    logger.info("Redis client initialized successfully")
except Exception as e:
    redis_client = None
    logger.warning(f"Redis initialization failed: {e}")
