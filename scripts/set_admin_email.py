import os, sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from app import app, db, Admin

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python scripts/set_admin_email.py your-email@example.com")
        sys.exit(1)

    new_email = sys.argv[1].strip()
    with app.app_context():
        admin = Admin.query.filter_by(username='admin').first()
        if not admin:
            print('No admin user found (username="admin").')
            sys.exit(2)
        old = admin.email
        admin.email = new_email
        db.session.commit()
        print(f"Admin email updated from {old} to {new_email}")
