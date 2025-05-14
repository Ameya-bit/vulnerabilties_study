# app.py
from flask import Flask, request, render_template_string, make_response
import html
import re

app = Flask(__name__)

### [1] INPUT VALIDATION ###
def validate_input(user_input: str) -> bool:
    """
    Implements allowlist validation for search queries
    Only allows alphanumeric characters and spaces
    """
    pattern = re.compile(r'^[a-zA-Z0-9 ]*$')  # Simple allowlist regex
    return bool(pattern.match(user_input))

### [2] CONTEXT-SENSITIVE OUTPUT ENCODING ###
def sanitize_output(user_input: str) -> str:
    """
    HTML-encodes special characters before rendering in templates
    Prevents script execution in HTML context
    """
    return html.escape(user_input)

### [3] CONTENT SECURITY POLICY (CSP) ###
@app.after_request
def apply_csp(response):
    """
    Sets strict CSP headers to prevent inline scripts and external resources
    """
    csp_policy = (
        "default-src 'self';"
        "script-src 'self';"
        "object-src 'none';"
        "style-src 'self' https://cdn.example.com;"
    )
    response.headers['Content-Security-Policy'] = csp_policy
    return response

### [4] SECURE HEADERS & COOKIES ###
@app.after_request
def set_security_headers(response):
    """Applies multiple security headers and cookie flags"""
    response.headers.update({
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'X-XSS-Protection': '1; mode=block'
    })
    response.set_cookie(
        'session_id',
        'secure_session_value',
        httponly=True,
        secure=True,
        samesite='Strict'
    )
    return response

### APPLICATION ROUTES ###
SEARCH_FORM = '''
<!DOCTYPE html>
<html>
<head>
    <title>Secure Search Demo</title>
</head>
<body>
    <h1>Protected Search</h1>
    <form method="GET" action="/search">
        <input type="text" name="query" required>
        <button type="submit">Search</button>
    </form>
    {% if result %}
    <div class="results">
        <h3>Results for: {{ result }}</h3>
    </div>
    {% endif %}
</body>
</html>
'''

@app.route('/')
def index():
    """Main page with search form"""
    return render_template_string(SEARCH_FORM)

@app.route('/search')
def search():
    """Handles search requests with security checks"""
    user_input = request.args.get('query', '')
    
    # Input validation
    if not validate_input(user_input):
        return "Invalid characters detected!", 400
    
    # Output encoding
    safe_output = sanitize_output(user_input)
    
    return render_template_string(SEARCH_FORM, result=safe_output)

if __name__ == '__main__':
    app.run(ssl_context='adhoc')  # Force HTTPS for demo purposes
