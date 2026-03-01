import sqlite3
import subprocess
import os
import logging
from markupsafe import Markup
from flask import (
    Flask, request, render_template, redirect,
    url_for, session, g, flash
)

app = Flask(__name__)
app.secret_key = 'weak-secret-key'

logging.basicConfig(
    filename=os.path.join(os.path.dirname(__file__), 'logs', 'access.log'), 
    level=logging.INFO,
    format='%(asctime)s | %(message)s'
)

#<--------- DATABASE --------->

DATABASE = os.path.join(os.path.dirname(__file__), 'logs', 'app.db')

def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(_exc):
    db = g.pop('db', None)
    if db:
        db.close()

def init_db():
    db = sqlite3.connect(DATABASE)
    db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT DEFAULT 'customer'
        );
        CREATE TABLE IF NOT EXISTS accounts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            holder TEXT NOT NULL,
            account_number TEXT UNIQUE,
            account_type TEXT,
            balance REAL
        );
        CREATE TABLE IF NOT EXISTS tickets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            author TEXT,
            content TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    """)

    try:
        db.execute("INSERT INTO users (username, password, role) VALUES ('admin', 'admin123', 'admin')")
        db.execute("INSERT INTO users (username, password, role) VALUES ('jsmith', 'password1', 'customer')")
        db.execute("INSERT INTO users (username, password, role) VALUES ('mjones', 'letmein', 'customer')")
        db.execute("INSERT INTO users (username, password, role) VALUES ('teller1', 'teller2024', 'teller')")
    except sqlite3.IntegrityError:
        pass  

    try:
        db.execute("INSERT INTO accounts (holder, account_number, account_type, balance) VALUES ('John Smith', '4820-0011-2233', 'Checking', 12450.75)")
        db.execute("INSERT INTO accounts (holder, account_number, account_type, balance) VALUES ('John Smith', '4820-0011-4455', 'Savings', 58320.00)")
        db.execute("INSERT INTO accounts (holder, account_number, account_type, balance) VALUES ('Mary Jones', '4820-0022-6677', 'Checking', 3215.50)")
        db.execute("INSERT INTO accounts (holder, account_number, account_type, balance) VALUES ('Mary Jones', '4820-0022-8899', 'Savings', 91000.00)")
        db.execute("INSERT INTO accounts (holder, account_number, account_type, balance) VALUES ('Robert Chen', '4820-0033-1122', 'Checking', 780.25)")
        db.execute("INSERT INTO accounts (holder, account_number, account_type, balance) VALUES ('Sarah Davis', '4820-0044-3344', 'Business', 245600.00)")
    except sqlite3.IntegrityError:
        pass

    db.commit()
    db.close()

#<--------- MiddleWare --------->

@app.before_request
def log_request():
    logging.info(
        f"method={request.method} path={request.path} "
        f"ip={request.remote_addr} "
        f"args={dict(request.args)} "
        f"form={dict(request.form)} "
        f"user_agent={request.headers.get('User-Agent', '')}"
    )

#<--------- Routes --------->

@app.route('/')
def index():
    return render_template('index.html', title="Home")

#V1 - SQL Injection + Brute Force
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')

        db = get_db()
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        app.logger.warning(f"Executing query: {query}")

        try:
            user = db.execute(query).fetchone()
            if user:
                session['username'] = user['username']
                session['role'] = user['role']
                flash(f"Welcome back, {user['username']}!")
                return redirect(url_for('profile'))
            else:
                flash("Invalid credentials. Please try again.")
        except Exception as e:
            flash(f"System error: {e}")

    return render_template('login.html', title="Login")


@app.route('/profile')
def profile():
    if not session.get('username'):
        return redirect(url_for('login'))

    db = get_db()
    accounts = db.execute("SELECT * FROM accounts").fetchall()
    return render_template('profile.html', title="Dashboard", accounts=accounts)


@app.route('/logout')
def logout():
    session.clear()
    flash("You have been signed out.")
    return redirect(url_for('index'))

#V2 - SQL Injection
@app.route('/accounts', methods=['GET', 'POST'])
def accounts():
    results = None
    error = None
    query_text = request.form.get('query', '') or request.args.get('query', '')

    if query_text:
        db = get_db()
        sql = f"SELECT * FROM accounts WHERE holder LIKE '%{query_text}%' OR account_number LIKE '%{query_text}%'"
        app.logger.warning(f"Executing query: {sql}")

        try:
            results = db.execute(sql).fetchall()
            if not results:
                results = None
        except Exception as e:
            error = str(e)

    return render_template('accounts.html', title="Account Lookup", results=results, error=error, query_text=query_text)

#V3 - XSS
@app.route('/support', methods=['GET', 'POST'])
def support():
    db = get_db()

    if request.method == 'POST':
        author = request.form.get('author', 'Anonymous')
        content_text = request.form.get('content', '')
        db.execute("INSERT INTO tickets (author, content) VALUES (?, ?)", (author, content_text))
        db.commit()
        flash("Support ticket submitted. A representative will review it shortly.")

    tickets = db.execute("SELECT * FROM tickets ORDER BY created_at DESC").fetchall()

    unsafe_tickets = []
    for t in tickets:
        unsafe_tickets.append({
            'author': Markup(t['author']),
            'content': Markup(t['content']),
            'created_at': t['created_at']
        })

    return render_template('support.html', title="Customer Support", tickets=unsafe_tickets)

#V4 - Command Injection
@app.route('/diagnostics', methods=['GET', 'POST'])
def diagnostics():
    output = ""
    target = request.form.get('target', '')

    if target:
        cmd = f"ping -c 2 {target}"
        app.logger.warning(f"Executing command: {cmd}")
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
            output = result.stdout + result.stderr
        except subprocess.TimeoutExpired:
            output = "Request timed out."
        except Exception as e:
            output = f"Error: {e}"

    return render_template('diagnostics.html', title="Network Diagnostics", output=output, target=target)


if __name__ == '__main__':
    init_db()
    print("\n" + "="*60)
    print("  VulnBank — Intentionally Vulnerable Banking App")
    print("  WARNING: Do NOT expose to public networks!")
    print("="*60)
    print("  Running on http://127.0.0.1:5000")
    print("="*60 + "\n")
    app.run(host='127.0.0.1', port=5000, debug=True)