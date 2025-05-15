# secure_app.py

from flask import Flask, request, render_template_string, redirect, url_for, make_response, jsonify
import re
import sqlite3
import bleach

app = Flask(__name__)

# === [1] DATABASE SETUP (for demonstration) ===
def init_db():
    conn = sqlite3.connect('comments.db')
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            content TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

init_db()

# === [2] INPUT VALIDATION ===
def validate_comment(comment: str) -> bool:
    """
    Allows letters, numbers, basic punctuation, and spaces.
    Adjust as needed for your use case.
    """
    pattern = re.compile(r'^[a-zA-Z0-9\s\-.,!?\'"]{1,250}$')
    return bool(pattern.fullmatch(comment))

# === [3] HTML SANITIZATION ===
def sanitize_html(content: str) -> str:
    """
    Uses Bleach to allow only safe tags and attributes.
    """
    allowed_tags = ['b', 'i', 'u', 'em', 'strong', 'br']
    allowed_attrs = {}
    return bleach.clean(content, tags=allowed_tags, attributes=allowed_attrs, strip=True)

# === [4] CSP & SECURITY HEADERS ===
@app.after_request
def set_security_headers(response):
    csp_policy = (
        "default-src 'self';"
        "script-src 'self';"
        "object-src 'none';"
        "style-src 'self';"
        "frame-ancestors 'none';"
        "report-uri /csp-report;"
    )
    response.headers['Content-Security-Policy'] = csp_policy
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.set_cookie(
        'session_id',
        'secure_session_value',
        httponly=True,
        secure=True,
        samesite='Strict'
    )
    return response

# === [5] CSP REPORT ENDPOINT ===
@app.route('/csp-report', methods=['POST'])
def csp_report():
    print("CSP Violation:", request.get_json())
    return '', 204

# === [6] TEMPLATES ===
PAGE_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>Secure Comments Demo</title>
</head>
<body>
    <h1>Leave a Comment</h1>
    <form method="POST" action="{{ url_for('submit_comment') }}">
        <textarea name="comment" rows="4" cols="40" required maxlength="250"></textarea><br>
        <button type="submit">Submit</button>
    </form>
    {% if error %}
        <p style="color:red;">{{ error }}</p>
    {% endif %}
    <h2>All Comments</h2>
    <ul>
        {% for c in comments %}
            <li>{{ c|safe }}</li>
        {% endfor %}
    </ul>
</body>
</html>
'''

# === [7] ROUTES ===
@app.route('/', methods=['GET'])
def index():
    conn = sqlite3.connect('comments.db')
    c = conn.cursor()
    c.execute('SELECT content FROM comments ORDER BY id DESC')
    comments = [row[0] for row in c.fetchall()]
    conn.close()
    return render_template_string(PAGE_TEMPLATE, comments=comments, error=None)

@app.route('/submit', methods=['POST'])
def submit_comment():
    comment = request.form.get('comment', '')
    if not validate_comment(comment):
        # Show error, do not store
        conn = sqlite3.connect('comments.db')
        c = conn.cursor()
        c.execute('SELECT content FROM comments ORDER BY id DESC')
        comments = [row[0] for row in c.fetchall()]
        conn.close()
        return render_template_string(PAGE_TEMPLATE, comments=comments, error="Invalid characters in comment!")
    # Sanitize and store
    safe_comment = sanitize_html(comment)
    conn = sqlite3.connect('comments.db')
    c = conn.cursor()
    c.execute('INSERT INTO comments (content) VALUES (?)', (safe_comment,))
    conn.commit()
    conn.close()
    return redirect(url_for('index'))

# === [8] RUN APP ===
if __name__ == '__main__':
    app.run(ssl_context='adhoc')  # HTTPS for demo
