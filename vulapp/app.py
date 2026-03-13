"""Main application entry point for the vulnerable web app."""
import os
from flask import Flask, request
from flask_smorest import Api
from werkzeug.middleware.proxy_fix import ProxyFix
from vulapp.config import FLASK_CONFIG
from vulapp.database import init_db
from vulapp.routes.web_routes import web_bp
from vulapp.routes.api_routes import api_blp
from vulapp.utils import get_echo, dict2str

# Initialize Flask app
# Get the directory containing this file (vulapp/)
basedir = os.path.abspath(os.path.dirname(__file__))
template_dir = os.path.join(basedir, 'templates')

app = Flask(__name__, template_folder=template_dir)
app.secret_key = FLASK_CONFIG['SECRET_KEY']

# Apply Flask configuration
for k, v in FLASK_CONFIG.items():
    if k != 'SECRET_KEY':
        app.config[k] = v

# Initialize API
api = Api(app)

# Handle proxy headers (like X-Forwarded-Proto from Nginx)
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

# Initialize database
init_db()

# Register blueprints
app.register_blueprint(web_bp)
api.register_blueprint(api_blp)


@app.before_request
def log_requests():
    """Log requests to welcome and API endpoints."""
    if request.path.startswith('/web/welcome-') or request.path.startswith('/api/v1/'):
        echo_data: str = dict2str(get_echo())

        # Log to file
        #log_entry = f"--- {datetime.now()} | {request.path} ---\n{echo_data}\n\n"
        #with open("welcome_requests.log", "a") as f:
        #    f.write(log_entry)

        print("\n--- REQUEST RECEIVED ---", flush=True)
        print(echo_data, flush=True)
        print("--- END REQUEST ---\n", flush=True)


if __name__ == '__main__':
    app.run(debug=True, port=5000, host='0.0.0.0')
