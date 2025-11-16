#!/usr/bin/env python3
"""
Migration script to add missing created_at column to findings table
"""

import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from sqlalchemy import text
from models import engine
from config import get_settings

def main():
    settings = get_settings()

    print("🔧 Fixing findings table schema...")
    print(f"Database: {settings.database_url.split('@')[1] if '@' in settings.database_url else 'local'}")

    with engine.connect() as conn:
        # Check if created_at column exists
        check_query = text("""
            SELECT column_name
            FROM information_schema.columns
            WHERE table_name = 'findings'
            AND column_name = 'created_at'
        """)

        result = conn.execute(check_query)
        exists = result.fetchone() is not None

        if exists:
            print("✅ Column 'created_at' already exists in findings table")
            return

        print("Adding 'created_at' column to findings table...")

        # Add the column with default value
        alter_query = text("""
            ALTER TABLE findings
            ADD COLUMN created_at TIMESTAMP DEFAULT NOW()
        """)

        conn.execute(alter_query)
        conn.commit()

        print("✅ Successfully added 'created_at' column")

        # Update existing rows to have discovered_at as created_at if null
        update_query = text("""
            UPDATE findings
            SET created_at = COALESCE(discovered_at, NOW())
            WHERE created_at IS NULL
        """)

        conn.execute(update_query)
        conn.commit()

        print("✅ Updated existing rows")

        # Verify
        verify_query = text("SELECT COUNT(*) FROM findings")
        result = conn.execute(verify_query)
        count = result.scalar()

        print(f"✅ Migration complete! {count} findings in database")

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"❌ Migration failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
