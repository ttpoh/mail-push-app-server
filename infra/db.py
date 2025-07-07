# infra/db.py
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
import os
from dotenv import load_dotenv

# .env 파일 로드
load_dotenv()

MYSQL_USER = os.getenv("MYSQL_USER")
MYSQL_PASSWORD = os.getenv("MYSQL_PASSWORD", "")  # 빈 비밀번호를 허용
MYSQL_HOST = os.getenv("MYSQL_HOST", "localhost")
MYSQL_PORT = os.getenv("MYSQL_PORT", "3306")
MYSQL_DB = os.getenv("MYSQL_DB")

# 환경 변수 디버깅
missing_vars = [var for var, value in [
    ("MYSQL_USER", MYSQL_USER),
    ("MYSQL_HOST", MYSQL_HOST),
    ("MYSQL_PORT", MYSQL_PORT),
    ("MYSQL_DB", MYSQL_DB)
] if value is None]

if missing_vars:
    raise ValueError(f"Missing environment variables: {missing_vars}")

# 디버깅을 위해 DATABASE_URL 출력
DATABASE_URL = f"mysql+pymysql://{MYSQL_USER}:{MYSQL_PASSWORD}@{MYSQL_HOST}:{MYSQL_PORT}/{MYSQL_DB}?charset=utf8mb4"
print(f"DATABASE_URL: {DATABASE_URL}")  # 디버깅용

engine = create_engine(
    DATABASE_URL,
    echo=False,
    pool_pre_ping=True,
    pool_size=5,
    max_overflow=10
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()