import os, sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from app import app, init_db
import json

if __name__ == '__main__':
    # Ensure DB + admin exist
    with app.app_context():
        init_db()
        # Enable dev helpers for this test
        app.config['DEV_SHOW_RESET_LINK'] = True
        app.config['DEV_ALLOW_RUNTIME_OVERRIDE'] = True
        app.config['ADMIN_API_SECRET'] = 'testsecret'

        client = app.test_client()

        # Set FORCE_RESET_RECIPIENT to the user's email
        resp = client.post('/dev/force-recipient', json={'email': 'shreyashpatil530@gmail.com', 'secret': 'testsecret'})
        print('SET RECIPIENT ->', resp.status_code, resp.get_json())

        # Trigger forgot password for admin
        resp2 = client.post('/admin/forgot', json={'username': 'admin'})
        print('FORGOT ->', resp2.status_code)
        try:
            print(json.dumps(resp2.get_json(), indent=2))
        except Exception:
            print('Response not JSON:', resp2.data)
