"""
Q-Secure | backend/seed.py
Seed the database with the default admin user.
Run: py -3 seed.py  (from backend/ directory)
"""
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.dirname(__file__))

from app import create_app
from extensions import db, bcrypt
from models.user   import User

def seed():
    app = create_app()
    with app.app_context():
        db.create_all()

        # Admin User
        admin_email = "admin@qsecure.local"
        if not User.query.filter_by(email=admin_email).first():
            u = User(email=admin_email,
                     password_hash=bcrypt.generate_password_hash("QSecure@2026").decode(),
                     role="admin")
            db.session.add(u)
            db.session.commit()

        print("\n" + "="*60)
        print("  Q-Secure Database Ready")
        print("="*60)
        print("  Default credentials:")
        print(f"    admin@qsecure.local  QSecure@2026")
        print("="*60)

if __name__ == "__main__":
    seed()
