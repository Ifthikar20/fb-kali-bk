"""
Migration: Add detailed evidence fields to findings table

This migration adds the following columns to the findings table:
- evidence (JSON): Technical evidence including headers, payloads, detection method
- remediation (JSON): Fix instructions, code examples, references
- cvss_score (Integer): CVSS score (0-10)
- cwe (String): CWE identifier
- owasp_category (String): OWASP Top 10 category
- created_at (DateTime): Timestamp when finding was created

Usage:
    python migrations/001_add_detailed_evidence_fields.py
"""

import sys
import os
from sqlalchemy import create_engine, text
from datetime import datetime

# Add parent directory to path to import config
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import get_settings

def run_migration():
    """Add new columns to findings table"""
    settings = get_settings()
    engine = create_engine(settings.database_url)

    print("=" * 80)
    print("MIGRATION: Adding detailed evidence fields to findings table")
    print("=" * 80)

    with engine.connect() as conn:
        # Check if columns already exist
        result = conn.execute(text("""
            SELECT column_name
            FROM information_schema.columns
            WHERE table_name = 'findings'
            AND column_name IN ('evidence', 'remediation', 'cvss_score', 'cwe', 'owasp_category', 'created_at')
        """))
        existing_columns = [row[0] for row in result]

        if existing_columns:
            print(f"⚠️  Warning: Some columns already exist: {existing_columns}")
            print("Skipping already-existing columns...")

        # Add evidence column (JSON)
        if 'evidence' not in existing_columns:
            print("Adding column: evidence (JSON)")
            conn.execute(text("ALTER TABLE findings ADD COLUMN evidence JSON DEFAULT '{}'::json"))
            conn.commit()
            print("✅ Added evidence column")
        else:
            print("⏭️  Skipping evidence column (already exists)")

        # Add remediation column (JSON)
        if 'remediation' not in existing_columns:
            print("Adding column: remediation (JSON)")
            conn.execute(text("ALTER TABLE findings ADD COLUMN remediation JSON DEFAULT '{}'::json"))
            conn.commit()
            print("✅ Added remediation column")
        else:
            print("⏭️  Skipping remediation column (already exists)")

        # Add cvss_score column (Integer)
        if 'cvss_score' not in existing_columns:
            print("Adding column: cvss_score (Integer)")
            conn.execute(text("ALTER TABLE findings ADD COLUMN cvss_score INTEGER"))
            conn.commit()
            print("✅ Added cvss_score column")
        else:
            print("⏭️  Skipping cvss_score column (already exists)")

        # Add cwe column (String)
        if 'cwe' not in existing_columns:
            print("Adding column: cwe (String 200)")
            conn.execute(text("ALTER TABLE findings ADD COLUMN cwe VARCHAR(200)"))
            conn.commit()
            print("✅ Added cwe column")
        else:
            print("⏭️  Skipping cwe column (already exists)")

        # Add owasp_category column (String)
        if 'owasp_category' not in existing_columns:
            print("Adding column: owasp_category (String 200)")
            conn.execute(text("ALTER TABLE findings ADD COLUMN owasp_category VARCHAR(200)"))
            conn.commit()
            print("✅ Added owasp_category column")
        else:
            print("⏭️  Skipping owasp_category column (already exists)")

        # Add created_at column (DateTime) - with default value for existing rows
        if 'created_at' not in existing_columns:
            print("Adding column: created_at (DateTime)")
            conn.execute(text("ALTER TABLE findings ADD COLUMN created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP"))
            conn.commit()
            print("✅ Added created_at column")
        else:
            print("⏭️  Skipping created_at column (already exists)")

    print("=" * 80)
    print("✅ MIGRATION COMPLETED SUCCESSFULLY")
    print("=" * 80)
    print("\nNew columns added to findings table:")
    print("  - evidence (JSON): Technical evidence")
    print("  - remediation (JSON): Fix instructions")
    print("  - cvss_score (Integer): CVSS score")
    print("  - cwe (String): CWE identifier")
    print("  - owasp_category (String): OWASP category")
    print("  - created_at (DateTime): Creation timestamp")
    print("\nYou can now restart the API to use the new fields.")
    print("=" * 80)

def rollback_migration():
    """Remove the added columns (rollback)"""
    settings = get_settings()
    engine = create_engine(settings.database_url)

    print("=" * 80)
    print("ROLLBACK: Removing detailed evidence fields from findings table")
    print("=" * 80)

    with engine.connect() as conn:
        columns_to_remove = ['evidence', 'remediation', 'cvss_score', 'cwe', 'owasp_category', 'created_at']

        for column in columns_to_remove:
            try:
                print(f"Removing column: {column}")
                conn.execute(text(f"ALTER TABLE findings DROP COLUMN IF EXISTS {column}"))
                conn.commit()
                print(f"✅ Removed {column} column")
            except Exception as e:
                print(f"⚠️  Error removing {column}: {e}")

    print("=" * 80)
    print("✅ ROLLBACK COMPLETED")
    print("=" * 80)

if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1 and sys.argv[1] == "rollback":
        confirmation = input("⚠️  WARNING: This will remove all detailed evidence data. Type 'yes' to confirm: ")
        if confirmation.lower() == 'yes':
            rollback_migration()
        else:
            print("Rollback cancelled.")
    else:
        run_migration()
