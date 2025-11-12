#!/usr/bin/env python3
"""
Database migration: Add evidence column to findings table
"""

import sys
from sqlalchemy import create_engine, text
from config import get_settings

def migrate():
    """Add evidence column to findings table"""
    settings = get_settings()
    engine = create_engine(settings.database_url)

    print("🔧 Running database migration: Add evidence column")
    print(f"   Database: {settings.database_url.split('@')[1] if '@' in settings.database_url else 'local'}")
    print()

    with engine.connect() as conn:
        # Check if column already exists
        result = conn.execute(text("""
            SELECT column_name
            FROM information_schema.columns
            WHERE table_name='findings' AND column_name='evidence'
        """))

        if result.fetchone():
            print("✅ Column 'evidence' already exists in findings table")
            return

        # Add evidence column
        print("📝 Adding 'evidence' column to findings table...")
        conn.execute(text("""
            ALTER TABLE findings
            ADD COLUMN IF NOT EXISTS evidence JSON DEFAULT '{}'::json
        """))
        conn.commit()

        print("✅ Successfully added 'evidence' column!")
        print()
        print("Migration complete! 🎉")

if __name__ == "__main__":
    try:
        migrate()
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ Migration failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
