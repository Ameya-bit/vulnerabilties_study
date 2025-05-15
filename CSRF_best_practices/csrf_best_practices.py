from flask import Flask, request, session, render_template_string, redirect, url_for

import os
import secrets

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Secure random secret key for session encryption

# CSRF Protection Middleware
@app.before_request
def csrf_protection():
    # Only check CSRF for authenticated users and for POST/PUT/DELETE
    if request.method in ["POST", "PUT", "DELETE"]:
        # Skip CSRF check for login
        if request.endpoint == 'login' or request.endpoint == 'login_form':
            return
        session_token = session.get('csrf_token')
        request_token = request.form.get('csrf_token') or request.headers.get('X-CSRF-Token')
        if not session_token or not request_token or not secrets.compare_digest(session_token, request_token):
            return "CSRF validation failed", 403

def generate_csrf_token():
    """Generate and store cryptographically secure CSRF token"""
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_urlsafe(64)
    return session['csrf_token']

# Inject CSRF token into all templates
app.jinja_env.globals['csrf_token'] = generate_csrf_token

# Secure Headers
@app.after_request
def set_security_headers(response):
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    return response

# GET /login: Render login form
@app.route('/login', methods=['GET'])
def login_form():
    html = '''
    <form method="POST" action="/login">
        <label>Username: <input type="text" name="username" required></label><br>
        <label>Password: <input type="password" name="password" required></label><br>
        <button type="submit">Login</button>
    </form>
    '''
    return render_template_string(html)

# POST /login: Handle login
@app.route('/', methods=['POST'])
@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    if valid_credentials(username, password):
        session.clear()
        session['authenticated'] = True
        session['username'] = username
        return redirect(url_for('email_form'))
    return "Invalid credentials", 401

def valid_credentials(username, password):
    # For demonstration only
    return True

# GET /update-email: Render email update form
@app.route('/update-email', methods=['GET'])
def email_form():
    html = '''
    <form method="POST" action="/update-email">
        <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
        <label>New Email: <input type="email" name="email" required></label>
        <button type="submit">Update</button>
    </form>
    '''
    return render_template_string(html)

# POST /update-email: Handle email update
@app.route('/update-email', methods=['POST'])
def update_email():
    if not session.get('authenticated'):
        return redirect(url_for('login_form'))
    new_email = request.form.get('email')
    session.pop('csrf_token', None)  # Rotate CSRF token
    return f"Email updated to {new_email}"

if __name__ == '__main__':
    # For local testing, you can use ssl_context='adhoc' for HTTPS
    app.run(ssl_context='adhoc', port=5000)
