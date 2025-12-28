import psycopg2
import sys

# Credentials from user
DB_HOST = "dpg-d58aj3mr433s73f5ie10-a.oregon-postgres.render.com"
DB_NAME = "teamrespect_xg0c"
DB_USER = "abdiwoli"
DB_PASS = "uEECpiM9ynCChnk26vp4Y0ECiutqeSVh"

# Usually external render hosts need a domain suffix, implying this might fail if it's internal only.
# But we test exactly what user gave.

print(f"Attempting to connect to {DB_HOST}...")

try:
    conn = psycopg2.connect(
        host=DB_HOST,
        database=DB_NAME,
        user=DB_USER,
        password=DB_PASS,
        connect_timeout=10
    )
    print("SUCCESS: Connection established!")
    conn.close()
except Exception as e:
    print(f"FAILURE: Could not connect.\nError: {e}")
    print("\nDIAGNOSIS:")
    print("If this failed with 'could not translate host name', it means 'dpg-...' is an internal Render address.")
    print("You need the EXTERNAL Database URL from the Render Dashboard to access it from home.")
