import sys
import os
from app import app, db, User

def promote_to_admin(username):
    print(f"Attempting to promote '{username}' to Admin...")
    
    with app.app_context():
        user = User.query.filter_by(username=username).first()
        
        if not user:
            print(f"Error: User '{username}' not found. Please register first.")
            return False
            
        if user.role == 'Admin':
            print(f"User '{username}' is already an Admin.")
            return True
            
        try:
            user.role = 'Admin'
            db.session.commit()
            print(f"SUCCESS: '{username}' is now an Admin!")
            return True
        except Exception as e:
            print(f"Error updating role: {e}")
            return False

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python promote_user.py <username>")
        print("Example: python promote_user.py abdiwoli")
        sys.exit(1)
        
    username = sys.argv[1]
    promote_to_admin(username)
