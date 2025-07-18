"""
Add missing columns to users table
"""
import psycopg2
import os
from urllib.parse import urlparse

def get_database_url():
    """Get database URL from environment"""
    return os.environ.get('DATABASE_URL') or os.environ.get('POSTGRES_URL')

def add_missing_columns():
    """Add missing columns to users table"""
    database_url = get_database_url()
    if not database_url:
        print("❌ No database URL found")
        return False
    
    try:
        # Parse the database URL
        parsed = urlparse(database_url)
        
        # Connect to database
        conn = psycopg2.connect(
            host=parsed.hostname,
            port=parsed.port or 5432,
            database=parsed.path[1:],  # Remove leading slash
            user=parsed.username,
            password=parsed.password,
            sslmode='require'
        )
        
        cur = conn.cursor()
        
        # Check which columns exist
        cur.execute("""
            SELECT column_name 
            FROM information_schema.columns 
            WHERE table_name = 'users'
        """)
        existing_columns = [row[0] for row in cur.fetchall()]
        print(f"✅ Existing columns: {existing_columns}")
        
        # Add missing columns
        columns_to_add = [
            ("failed_login_attempts", "INTEGER DEFAULT 0"),
            ("account_locked_until", "TIMESTAMP"),
            ("last_login_at", "TIMESTAMP"),
            ("last_login_ip", "VARCHAR(45)")
        ]
        
        for column_name, column_def in columns_to_add:
            if column_name not in existing_columns:
                try:
                    cur.execute(f"ALTER TABLE users ADD COLUMN {column_name} {column_def}")
                    print(f"✅ Added column: {column_name}")
                except Exception as e:
                    print(f"❌ Failed to add {column_name}: {e}")
        
        # Commit changes
        conn.commit()
        cur.close()
        conn.close()
        
        print("✅ Database schema updated successfully")
        return True
        
    except Exception as e:
        print(f"❌ Database update failed: {e}")
        return False

if __name__ == "__main__":
    add_missing_columns()
