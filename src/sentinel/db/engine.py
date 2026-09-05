"""
FlagThis Sentinel Database Engine.

Configures asynchronous SQLAlchemy with SQLite WAL mode and busy timeouts.
"""

from pathlib import Path
from sqlalchemy.ext.asyncio import (
    create_async_engine,
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
)
from sqlalchemy import event
from sentinel.db.models import Base


def configure_sqlite_pragmas(dbapi_connection, connection_record):
    """Enforce WAL mode, foreign keys, and 5000ms busy timeout on SQLite connections."""
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA journal_mode=WAL;")
    cursor.execute("PRAGMA busy_timeout=15000;")
    cursor.execute("PRAGMA foreign_keys=ON;")
    cursor.close()


class DatabaseManager:
    def __init__(self, database_url: str = "sqlite+aiosqlite:///data/sentinel.db", wal_mode: bool = True):
        # Ensure directory exists for sqlite files
        if database_url.startswith("sqlite+aiosqlite:///"):
            file_path = database_url.replace("sqlite+aiosqlite:///", "")
            if file_path != ":memory:":
                Path(file_path).parent.mkdir(parents=True, exist_ok=True)

        self.engine: AsyncEngine = create_async_engine(
            database_url,
            echo=False,
            future=True,
        )

        if "sqlite" in database_url and wal_mode:
            event.listen(self.engine.sync_engine, "connect", configure_sqlite_pragmas)

        self.session_factory = async_sessionmaker(
            bind=self.engine,
            class_=AsyncSession,
            expire_on_commit=False,
        )

    async def init_db(self) -> None:
        """Create database tables if they do not exist and apply schema migrations."""
        async with self.engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

            # SQLite schema migration for all added columns in v2.1.x
            def _migrate_columns(sync_conn):
                cursor = sync_conn.cursor() if hasattr(sync_conn, "cursor") else sync_conn.connection.cursor()
                try:
                    # 1. squat_detections migrations
                    cursor.execute("PRAGMA table_info(squat_detections);")
                    det_cols = {row[1] for row in cursor.fetchall()}
                    if "content_hash" not in det_cols:
                        cursor.execute("ALTER TABLE squat_detections ADD COLUMN content_hash VARCHAR(64);")
                    if "created_at" not in det_cols:
                        cursor.execute("ALTER TABLE squat_detections ADD COLUMN created_at DATETIME;")
                    if "updated_at" not in det_cols:
                        cursor.execute("ALTER TABLE squat_detections ADD COLUMN updated_at DATETIME;")
                    if "priority_tier" not in det_cols:
                        cursor.execute("ALTER TABLE squat_detections ADD COLUMN priority_tier INTEGER NOT NULL DEFAULT 2;")
                    if "audit_count" not in det_cols:
                        cursor.execute("ALTER TABLE squat_detections ADD COLUMN audit_count INTEGER NOT NULL DEFAULT 1;")
                    if "last_audited_at" not in det_cols:
                        cursor.execute("ALTER TABLE squat_detections ADD COLUMN last_audited_at DATETIME;")
                    if "next_audit_due_at" not in det_cols:
                        cursor.execute("ALTER TABLE squat_detections ADD COLUMN next_audit_due_at DATETIME;")
                    if "needs_reprocess" not in det_cols:
                        cursor.execute("ALTER TABLE squat_detections ADD COLUMN needs_reprocess BOOLEAN NOT NULL DEFAULT 0;")
                    if "refresh_network_data" not in det_cols:
                        cursor.execute("ALTER TABLE squat_detections ADD COLUMN refresh_network_data BOOLEAN NOT NULL DEFAULT 0;")
                    if "reprocess_priority" not in det_cols:
                        cursor.execute("ALTER TABLE squat_detections ADD COLUMN reprocess_priority INTEGER NOT NULL DEFAULT 100;")
                    if "reprocess_reason" not in det_cols:
                        cursor.execute("ALTER TABLE squat_detections ADD COLUMN reprocess_reason VARCHAR(128);")
                    if "has_install_hook" not in det_cols:
                        cursor.execute("ALTER TABLE squat_detections ADD COLUMN has_install_hook BOOLEAN NOT NULL DEFAULT 0;")
                        cursor.execute("CREATE INDEX IF NOT EXISTS idx_detection_install_hook ON squat_detections (ecosystem, has_install_hook, threat_score);")
                    if "has_network_socket" not in det_cols:
                        cursor.execute("ALTER TABLE squat_detections ADD COLUMN has_network_socket BOOLEAN NOT NULL DEFAULT 0;")
                    if "is_deprecated" not in det_cols:
                        cursor.execute("ALTER TABLE squat_detections ADD COLUMN is_deprecated BOOLEAN NOT NULL DEFAULT 0;")
                        cursor.execute("CREATE INDEX IF NOT EXISTS idx_detection_deprecated ON squat_detections (ecosystem, is_deprecated);")
                    if "deprecation_reason" not in det_cols:
                        cursor.execute("ALTER TABLE squat_detections ADD COLUMN deprecation_reason VARCHAR(512);")

                    # Backfill any null timestamps
                    cursor.execute("UPDATE squat_detections SET created_at = published_at WHERE created_at IS NULL;")
                    cursor.execute("UPDATE squat_detections SET updated_at = published_at WHERE updated_at IS NULL;")
                    cursor.execute("UPDATE squat_detections SET last_audited_at = published_at WHERE last_audited_at IS NULL;")

                    # 2. registered_packages migrations
                    cursor.execute("PRAGMA table_info(registered_packages);")
                    reg_cols = {row[1] for row in cursor.fetchall()}
                    if "is_brand_target" not in reg_cols:
                        cursor.execute("ALTER TABLE registered_packages ADD COLUMN is_brand_target BOOLEAN NOT NULL DEFAULT 0;")
                    if "priority_score" not in reg_cols:
                        cursor.execute("ALTER TABLE registered_packages ADD COLUMN priority_score INTEGER NOT NULL DEFAULT 10;")
                    if "crawled_at" not in reg_cols:
                        cursor.execute("ALTER TABLE registered_packages ADD COLUMN crawled_at DATETIME;")
                    if "matches_grammar" not in reg_cols:
                        cursor.execute("ALTER TABLE registered_packages ADD COLUMN matches_grammar BOOLEAN NOT NULL DEFAULT 0;")
                        cursor.execute("CREATE INDEX IF NOT EXISTS idx_registered_grammar_backfill ON registered_packages (ecosystem, matches_grammar, crawled_at);")

                    # 3. sentinel_jobs_queue migrations
                    cursor.execute("PRAGMA table_info(sentinel_jobs_queue);")
                    job_cols = {row[1] for row in cursor.fetchall()}
                    if "refresh_network_data" not in job_cols:
                        cursor.execute("ALTER TABLE sentinel_jobs_queue ADD COLUMN refresh_network_data BOOLEAN NOT NULL DEFAULT 0;")

                except Exception:
                    pass
                finally:
                    cursor.close()

            await conn.run_sync(_migrate_columns)

    async def close(self) -> None:
        """Close database engine connection pool."""
        await self.engine.dispose()

    def get_session(self) -> AsyncSession:
        """Get an async database session."""
        return self.session_factory()
