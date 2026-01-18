import os, sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from app import app, init_db
import json

if __name__ == '__main__':
    with app.app_context():
        init_db()
        app.config['DEV_SHOW_RESET_LINK'] = True
        client = app.test_client()

        resp = client.post('/admin/forgot', json={'username': 'admin'})
        print('Status:', resp.status_code)
        print(json.dumps(resp.get_json(), indent=2))
