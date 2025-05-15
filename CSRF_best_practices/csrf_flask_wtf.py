from flask import Flask, render_template_string, redirect, url_for, session
from flask_wtf import FlaskForm, CSRFProtect
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)  # Secure random secret key

# Enable CSRF protection for the entire app
csrf = CSRFProtect(app)

# Define the login form using Flask-WTF
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

# Define the email update form using Flask-WTF
class EmailForm(FlaskForm):
    email = StringField('New Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Update')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        # Stub for credential validation
        if form.username.data == 'user' and form.password.data == 'pass':
            session.clear()
            session['authenticated'] = True
            session['username'] = form.username.data
            return redirect(url_for('update_email'))
        else:
            return "Invalid credentials", 401
    # Render login form with CSRF token included
    return render_template_string('''
    <form method="POST">
        {{ form.hidden_tag() }}  <!-- CSRF token and other hidden fields -->
        {{ form.username.label }} {{ form.username() }}<br>
        {{ form.password.label }} {{ form.password() }}<br>
        {{ form.submit() }}
    </form>
    ''', form=form)

@app.route('/update-email', methods=['GET', 'POST'])
def update_email():
    if not session.get('authenticated'):
        return redirect(url_for('login'))
    form = EmailForm()
    if form.validate_on_submit():
        new_email = form.email.data
        # Here you would update the email in your database
        return f"Email updated to {new_email}"
    # Render email update form with CSRF token included
    return render_template_string('''
    <form method="POST">
        {{ form.hidden_tag() }}  <!-- CSRF token and other hidden fields -->
        {{ form.email.label }} {{ form.email() }}<br>
        {{ form.submit() }}
    </form>
    ''', form=form)

if __name__ == '__main__':
    app.run(ssl_context='adhoc', port=5000)
