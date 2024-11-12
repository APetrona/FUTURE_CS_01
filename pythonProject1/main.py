from flask import Flask, render_template, request, redirect, url_for, flash, session
import pyotp

app = Flask(__name__)
app.secret_key = 'supersecretkey'  # Replace with a secure secret key

# Define your TOTP secret key
key = "TronaAwuorMySuperSecretKey"
totp = pyotp.TOTP(key)

# Dummy user credentials for demonstration purposes
USER_CREDENTIALS = {
    "username": "Petrona",
    "password": "password123"  # Use a hashed password in production
}


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Validate username and password
        if username == USER_CREDENTIALS['username'] and password == USER_CREDENTIALS['password']:
            session['username'] = username
            flash('Login successful. Enter 2FA code to complete login.', 'success')
            return redirect(url_for('verify'))
        else:
            flash('Invalid username or password.', 'danger')

    return render_template('login.html')


@app.route('/verify', methods=['GET', 'POST'])
def verify():
    if 'username' not in session:
        flash('Please log in first.', 'danger')
        return redirect(url_for('login'))

    if request.method == 'POST':
        code = request.form['code']
        if totp.verify(code):
            flash('2FA verification successful!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Invalid 2FA code. Please try again.', 'danger')

    return render_template('verify.html')


@app.route('/')
def index():
    if 'username' in session:
        return render_template('index.html')
    else:
        return redirect(url_for('login'))


@app.route('/logout')
def logout():
    session.pop('username', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/home')
def home():
    return render_template('home.html')

if __name__ == '__main__':
    app.run(debug=True)
