import psycopg2
import os
from urllib.parse import urlparse

database_url = os.environ.get('DATABASE_URL') or os.environ.get('POSTGRES_URL')
if database_url:
    try:
        parsed = urlparse(database_url)
        conn = psycopg2.connect(
            host=parsed.hostname,
            port=parsed.port or 5432,
            database=parsed.path[1:],
            user=parsed.username,
            password=parsed.password,
            sslmode='require'
        )
        cur = conn.cursor()
        cur.execute("SELECT column_name FROM information_schema.columns WHERE table_name = 'users' ORDER BY column_name")
        columns = [row[0] for row in cur.fetchall()]
        print("📋 All users table columns:")
        for col in columns:
            print(f"  - {col}")
        cur.close()
        conn.close()
    except Exception as e:
        print(f"❌ Verification failed: {e}")
