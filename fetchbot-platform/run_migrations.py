"""
Auto-run database migrations on startup

This script checks and applies necessary migrations to the database.
It's designed to be called automatically when the API starts.
"""

import logging
from sqlalchemy import create_engine, text, inspect
from config import get_settings

logger = logging.getLogger(__name__)

def check_and_migrate():
    """Check database schema and apply migrations if needed"""
    settings = get_settings()
    engine = create_engine(settings.database_url)

    try:
        inspector = inspect(engine)

        # Check if findings table exists
        if 'findings' not in inspector.get_table_names():
            logger.info("Findings table doesn't exist yet - will be created by init_db()")
            return

        # Get existing columns
        columns = inspector.get_columns('findings')
        column_names = [col['name'] for col in columns]

        # Define required new columns
        migrations_needed = []

        if 'evidence' not in column_names:
            migrations_needed.append(('evidence', "JSON DEFAULT '{}'::json"))
        if 'remediation' not in column_names:
            migrations_needed.append(('remediation', "JSON DEFAULT '{}'::json"))
        if 'cvss_score' not in column_names:
            migrations_needed.append(('cvss_score', 'INTEGER'))
        if 'cwe' not in column_names:
            migrations_needed.append(('cwe', 'VARCHAR(200)'))
        if 'owasp_category' not in column_names:
            migrations_needed.append(('owasp_category', 'VARCHAR(200)'))
        if 'created_at' not in column_names:
            migrations_needed.append(('created_at', 'TIMESTAMP DEFAULT CURRENT_TIMESTAMP'))

        if migrations_needed:
            logger.info("=" * 60)
            logger.info("DATABASE MIGRATION: Adding detailed evidence fields")
            logger.info("=" * 60)

            with engine.connect() as conn:
                for column_name, column_def in migrations_needed:
                    logger.info(f"Adding column: {column_name}")
                    try:
                        conn.execute(text(f"ALTER TABLE findings ADD COLUMN {column_name} {column_def}"))
                        conn.commit()
                        logger.info(f"✅ Added {column_name} column")
                    except Exception as e:
                        logger.warning(f"⚠️  Could not add {column_name}: {e}")

            logger.info("=" * 60)
            logger.info("✅ DATABASE MIGRATION COMPLETED")
            logger.info("=" * 60)
        else:
            logger.info("✅ Database schema is up to date")

    except Exception as e:
        logger.error(f"Migration check failed: {e}")
        # Don't crash the app if migration fails - just log it

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    check_and_migrate()
