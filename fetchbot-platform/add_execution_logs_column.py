"""
Database Migration: Add execution_logs column to pentest_jobs table
Run this once to update the database schema
"""
import psycopg2
from config import get_settings

settings = get_settings()

# Parse DATABASE_URL
# Format: postgresql://user:password@host:port/database
db_url = settings.database_url
# Extract components
db_url = db_url.replace('postgresql://', '')
user_pass, host_db = db_url.split('@')
user, password = user_pass.split(':')
host_port, database = host_db.split('/')
host, port = host_port.split(':')

print(f"Connecting to database: {database} on {host}:{port}")

try:
    # Connect to PostgreSQL
    conn = psycopg2.connect(
        host=host,
        port=port,
        database=database,
        user=user,
        password=password
    )

    cursor = conn.cursor()

    # Check if column exists
    cursor.execute("""
        SELECT column_name
        FROM information_schema.columns
        WHERE table_name='pentest_jobs' AND column_name='execution_logs';
    """)

    exists = cursor.fetchone()

    if exists:
        print("✅ Column 'execution_logs' already exists!")
    else:
        print("Adding 'execution_logs' column to pentest_jobs table...")

        # Add the column
        cursor.execute("""
            ALTER TABLE pentest_jobs
            ADD COLUMN execution_logs JSON DEFAULT '[]'::json;
        """)

        conn.commit()
        print("✅ Column 'execution_logs' added successfully!")

    cursor.close()
    conn.close()
    print("✅ Migration completed!")

except Exception as e:
    print(f"❌ Migration failed: {e}")
    import traceback
    traceback.print_exc()
