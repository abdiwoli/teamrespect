from app import app, db, User

with app.app_context():
    users = User.query.all()
    print(f"\nFound {len(users)} registered users:")
    for u in users:
        print(f" - Username: {u.username}, Role: {u.role}")
