from flask import Flask, render_template, request, redirect, url_for, session, flash
import os
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'your-secret-key-change-this-in-production'

# In-memory storage for users (in production, use a proper database)
users = {}

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('home'))
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        first_name = request.form.get('first_name', '').strip()
        last_name = request.form.get('last_name', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        
        # Validation
        if not all([first_name, last_name, email, password, confirm_password]):
            flash('All fields are required.', 'error')
            return render_template('register.html')
        
        if password != confirm_password:
            flash('Passwords do not match. Please re-enter your password.', 'error')
            return render_template('register.html')
        
        if len(password) < 6:
            flash('Password must be at least 6 characters long.', 'error')
            return render_template('register.html')
        
        if email in users:
            flash('An account with this email already exists.', 'error')
            return render_template('register.html')
        
        # Create new user
        users[email] = {
            'first_name': first_name,
            'last_name': last_name,
            'email': email,
            'password': generate_password_hash(password)
        }
        
        flash('Account created successfully! You can now login.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        
        if not email or not password:
            flash('Please enter both email and password.', 'error')
            return render_template('login.html')
        
        user = users.get(email)
        if user and check_password_hash(user['password'], password):
            session['user_id'] = email
            session['user_name'] = user['first_name']
            return redirect(url_for('home'))
        else:
            flash('Invalid email or password.', 'error')
    
    return render_template('login.html')

@app.route('/home')
def home():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('home.html', user_name=session.get('user_name'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

if __name__ == '__main__':
    # Create demo user
    users['demo@example.com'] = {
        'first_name': 'Demo',
        'last_name': 'User',
        'email': 'demo@example.com',
        'password': generate_password_hash('demo123')
    }
    
    app.run(debug=True, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))