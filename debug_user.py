from app import app, db, User
import sys

def list_users():
    with app.app_context():
        users = User.query.all()
        print("\n--- Users in Database ---")
        if not users:
            print("No users found!")
        for u in users:
            print(f"ID: {u.id} | Username: {u.username} | Role: {u.role}")
        print("-------------------------\n")

def reset_password(username, new_password):
    with app.app_context():
        user = User.query.filter_by(username=username).first()
        if user:
            user.set_password(new_password)
            db.session.commit()
            print(f"SUCCESS: Password for '{username}' has been updated.")
        else:
            print(f"ERROR: User '{username}' not found.")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        if sys.argv[1] == "list":
            list_users()
        elif sys.argv[1] == "reset" and len(sys.argv) == 4:
            reset_password(sys.argv[2], sys.argv[3])
        else:
            print("Usage:")
            print("  python debug_user.py list              (Show all users)")
            print("  python debug_user.py reset <user> <pw> (Reset password)")
    else:
        list_users()
