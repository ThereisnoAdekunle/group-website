from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import smtplib
from email.mime.text import MIMEText
from ssl import create_default_context
import os

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'your-secret-key-here')

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin):
    def __init__(self, id, email, name, is_admin):
        self.id = id
        self.email = email
        self.name = name
        self.is_admin = is_admin

@login_manager.user_loader
def load_user(user_id):
    conn = sqlite3.connect(os.path.join(os.path.dirname(__file__), 'group.db'))
    c = conn.cursor()
    c.execute("SELECT id, email, name, is_admin FROM users WHERE id = ?", (user_id,))
    user_data = c.fetchone()
    conn.close()
    if user_data:
        return User(user_data[0], user_data[1], user_data[2], user_data[3])
    return None

def init_db():
    conn = sqlite3.connect(os.path.join(os.path.dirname(__file__), 'group.db'))
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users 
                 (id INTEGER PRIMARY KEY, name TEXT, email TEXT UNIQUE, password_hash TEXT, is_admin INTEGER DEFAULT 0)''')
    c.execute('''CREATE TABLE IF NOT EXISTS contributions 
                 (id INTEGER PRIMARY KEY, user_id INTEGER, amount REAL, date TEXT, status INTEGER DEFAULT 0, 
                 FOREIGN KEY (user_id) REFERENCES users(id))''')
    c.execute("PRAGMA table_info(users)")
    if 'is_admin' not in [col[1] for col in c.fetchall()]:
        c.execute("ALTER TABLE users ADD COLUMN is_admin INTEGER DEFAULT 0")
    c.execute("PRAGMA table_info(contributions)")
    columns = [col[1] for col in c.fetchall()]
    if 'approved' in columns and 'status' not in columns:
        c.execute("ALTER TABLE contributions RENAME COLUMN approved TO status")
    elif 'status' not in columns:
        c.execute("ALTER TABLE contributions ADD COLUMN status INTEGER DEFAULT 0")
    c.execute("SELECT id, is_admin FROM users WHERE email = ?", ('westkhalifahninety7@gmail.com',))
    user = c.fetchone()
    if user and user[1] != 1:
        c.execute("UPDATE users SET is_admin = 1 WHERE email = ?", ('westkhalifahninety7@gmail.com',))
    elif not user:
        default_password = generate_password_hash('admin123')
        c.execute("INSERT OR IGNORE INTO users (name, email, password_hash, is_admin) VALUES (?, ?, ?, 1)", 
                  ('Admin', 'westkhalifahninety7@gmail.com', default_password))
    conn.commit()
    conn.close()

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        conn = sqlite3.connect(os.path.join(os.path.dirname(__file__), 'group.db'))
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE email = ?", (email,))
        user_data = c.fetchone()
        conn.close()
        if user_data and check_password_hash(user_data[3], password):
            user = User(user_data[0], user_data[2], user_data[1], user_data[4])
            login_user(user)
            return redirect(url_for('home'))
        flash('Invalid email or password')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        password_hash = generate_password_hash(password)
        conn = sqlite3.connect(os.path.join(os.path.dirname(__file__), 'group.db'))
        c = conn.cursor()
        try:
            c.execute("INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)", 
                      (name, email, password_hash))
            conn.commit()
            conn.close()
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Email already registered')
            conn.close()
    return render_template('register.html')

@app.route('/', methods=['GET', 'POST'])
@login_required
def home():
    conn = sqlite3.connect(os.path.join(os.path.dirname(__file__), 'group.db'))
    c = conn.cursor()
    
    if request.method == 'POST':
        amount = float(request.form['amount'])
        date = request.form['date']
        c.execute("INSERT INTO contributions (user_id, amount, date, status) VALUES (?, ?, ?, 0)", 
                  (current_user.id, amount, date))
        conn.commit()

        msg = MIMEText(f"Hi {current_user.name},\n\nYou submitted ₦{amount} on {date}. It’s pending admin approval.\n\nThanks for your support!")
        msg['Subject'] = 'Contribution Submitted'
        msg['From'] = 'westkhalifahninety7@gmail.com'
        msg['To'] = current_user.email
        
        try:
            server = smtplib.SMTP_SSL('smtp.gmail.com', 465, timeout=10, context=create_default_context())
            server.login('westkhalifahninety7@gmail.com', 'gdnzdvuzfcosizpu')
            server.send_message(msg)
            server.quit()
        except smtplib.SMTPException as e:
            flash(f"SMTP error: {str(e)}")
        except Exception as e:
            flash(f"General error: {str(e)}")

        flash('Contribution submitted! Awaiting admin approval.')
        return redirect(url_for('home'))

    # Calculate total approved contributions
    c.execute("SELECT SUM(amount) FROM contributions WHERE status = 1")
    total_contributed = c.fetchone()[0] or 0.0
    conn.close()
    
    return render_template('index.html', total_contributed=total_contributed)

@app.route('/leaderboard')
@login_required
def leaderboard():
    conn = sqlite3.connect(os.path.join(os.path.dirname(__file__), 'group.db'))
    c = conn.cursor()
    c.execute('''SELECT u.name, SUM(c.amount) as total 
                 FROM users u 
                 LEFT JOIN contributions c ON u.id = c.user_id 
                 WHERE c.status = 1 
                 GROUP BY u.id, u.name 
                 ORDER BY total DESC''')
    raw_data = c.fetchall()
    conn.close()
    leaderboard_data = [(i + 1, name, total) for i, (name, total) in enumerate(raw_data)]
    return render_template('leaderboard.html', leaderboard=leaderboard_data)

@app.route('/history')
@login_required
def history():
    conn = sqlite3.connect(os.path.join(os.path.dirname(__file__), 'group.db'))
    c = conn.cursor()
    c.execute('''SELECT amount, date, status 
                 FROM contributions 
                 WHERE user_id = ? 
                 ORDER BY date DESC''', (current_user.id,))
    history_data = c.fetchall()
    conn.close()
    return render_template('history.html', history=history_data)

@app.route('/admin', methods=['GET', 'POST'])
@login_required
def admin():
    if not current_user.is_admin:
        flash('Admin access only.')
        return redirect(url_for('home'))
    
    conn = sqlite3.connect(os.path.join(os.path.dirname(__file__), 'group.db'))
    c = conn.cursor()
    
    if request.method == 'POST':
        contribution_id = request.form.get('contribution_id')
        action = request.form.get('action')
        if action == 'approve':
            c.execute("UPDATE contributions SET status = 1 WHERE id = ?", (contribution_id,))
        elif action == 'reject':
            c.execute("UPDATE contributions SET status = 2 WHERE id = ?", (contribution_id,))
        elif action == 'pending':
            c.execute("UPDATE contributions SET status = 0 WHERE id = ?", (contribution_id,))
        conn.commit()
        flash('Contribution status updated!')
    
    c.execute('''SELECT c.id, u.name, c.amount, c.date, c.status 
                 FROM contributions c 
                 JOIN users u ON c.user_id = u.id 
                 ORDER BY c.date DESC''')
    contributions = c.fetchall()
    conn.close()
    return render_template('admin.html', contributions=contributions)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

if __name__ == '__main__':
    init_db()
    port = int(os.getenv('PORT', 5000))
    app.run(host='0.0.0.0', port=port)