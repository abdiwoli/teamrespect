from app import app, db, Member
import os

print(f"Checking database connection string...")
# print(app.config['SQLALCHEMY_DATABASE_URI']) # Security: Don't print full creds
uri = app.config['SQLALCHEMY_DATABASE_URI']
if 'render.com' in uri:
    print("CONFIRMED: Connected to EXTERNAL Render Database")
elif 'sqlite' in uri:
    print("WARNING: Connected to LOCAL SQLite file")
else:
    print(f"Unknown DB: {uri[:15]}...")

with app.app_context():
    members = Member.query.all()
    with open('db_members.txt', 'w') as f:
        f.write(f"Found {len(members)} total members in this database:\n")
        for m in members:
            f.write(f" - ID: {m.id}, Name: {m.name} (Joined: {m.joined_date})\n")
    print("Done writing to db_members.txt")
