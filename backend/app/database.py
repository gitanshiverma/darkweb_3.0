import os
from pathlib import Path
from sqlalchemy import create_engine, text
from sqlalchemy.orm import declarative_base, sessionmaker
from dotenv import load_dotenv

load_dotenv()

POSTGRES_PORT = os.getenv("POSTGRES_PORT", "5432")
POSTGRES_DB = os.getenv("POSTGRES_DB", "sih_darkweb")
POSTGRES_USER = os.getenv("POSTGRES_USER", "sih_user")
POSTGRES_PASSWORD = os.getenv("POSTGRES_PASSWORD", "sih_password")
ENV_POSTGRES_HOST = os.getenv("POSTGRES_HOST", "localhost")


def create_resilient_engine():
    # 1. Prefer a full connection string if provided
    full_url = os.getenv("DATABASE_URL") or os.getenv("POSTGRES_URL")
    if full_url:
        try:
            eng = create_engine(full_url, pool_pre_ping=True)
            with eng.connect() as conn:
                conn.execute(text("SELECT 1"))
            return eng
        except Exception as e:
            print(f"[database] full_url connection failed: {e}")

    # 2. Fall back to piecemeal host attempts
    candidate_hosts = [ENV_POSTGRES_HOST]
    for h in ["localhost", "127.0.0.1", "postgres"]:
        if h not in candidate_hosts:
            candidate_hosts.append(h)

    for host in candidate_hosts:
        url = f"postgresql+psycopg://{POSTGRES_USER}:{POSTGRES_PASSWORD}@{host}:{POSTGRES_PORT}/{POSTGRES_DB}"
        try:
            eng = create_engine(url, pool_pre_ping=True)
            with eng.connect() as conn:
                conn.execute(text("SELECT 1"))
            return eng
        except Exception as e:
            print(f"[database] host {host} failed: {e}")
            continue

    # 3. Last-resort SQLite fallback
    print("[database] WARNING: falling back to local SQLite")
    backend_dir = Path(__file__).resolve().parents[1]
    db_path = backend_dir / "app.db"
    return create_engine(
        f"sqlite:///{db_path.as_posix()}",
        connect_args={"check_same_thread": False},
    )


engine = create_resilient_engine()

SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine,
)

Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    from . import models  # noqa: F401
    Base.metadata.create_all(bind=engine)