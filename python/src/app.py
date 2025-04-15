from flask import Flask, request, render_template_string, redirect, session
import sqlite3
import os
import subprocess
import yaml
import pickle
import base64

app = Flask(__name__)
app.secret_key = "super_secret_key_1234567890"  # Hardcoded secret key

# Database setup
def init_db():
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY,
        username TEXT,
        password TEXT,
        admin INTEGER
    )
    ''')
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS notes (
        id INTEGER PRIMARY KEY,
        user_id INTEGER,
        content TEXT
    )
    ''')
    # Insert admin user with weak password
    cursor.execute("INSERT OR IGNORE INTO users (id, username, password, admin) VALUES (1, 'admin', 'admin123', 1)")
    conn.commit()
    conn.close()

# Create database and tables
init_db()

# VULNERABILITY: Hardcoded credentials
DATABASE_CONFIG = {
    'host': 'localhost',
    'user': 'dbuser',
    'password': 'Password123!',
    'database': 'vulnerable_db'
}

# VULNERABILITY: SQL Injection
@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Vulnerable SQL query - direct string interpolation
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        query = f"SELECT id, username FROM users WHERE username = '{username}' AND password = '{password}'"
        cursor.execute(query)
        user = cursor.fetchone()
        conn.close()
        
        if user:
            session['user_id'] = user[0]
            session['username'] = user[1]
            return redirect('/dashboard')
        else:
            error = 'Invalid credentials'
    
    return '''
        <form method="post">
            <input type="text" name="username" placeholder="Username">
            <input type="password" name="password" placeholder="Password">
            <input type="submit" value="Login">
        </form>
    '''

# VULNERABILITY: XSS (Cross-Site Scripting)
@app.route('/search')
def search():
    query = request.args.get('q', '')
    # Vulnerable template - directly injecting user input
    template = f'''
        <h1>Search Results for: {query}</h1>
        <p>No results found.</p>
        <a href="/">Back to Home</a>
    '''
    return render_template_string(template)

# VULNERABILITY: Command Injection
@app.route('/ping', methods=['GET', 'POST'])
def ping():
    if request.method == 'POST':
        hostname = request.form['hostname']
        # Vulnerable command execution - direct command injection
        result = subprocess.check_output(f"ping -c 1 {hostname}", shell=True)
        return f"<pre>{result.decode()}</pre>"
    return '''
        <form method="post">
            <input type="text" name="hostname" placeholder="Enter hostname">
            <input type="submit" value="Ping">
        </form>
    '''

# VULNERABILITY: Insecure Deserialization
@app.route('/object')
def object_page():
    serialized = request.args.get('data')
    if serialized:
        # Vulnerable deserialization - loading arbitrary pickle data
        obj = pickle.loads(base64.b64decode(serialized))
        return str(obj)
    return "No data provided"

# VULNERABILITY: Path Traversal
@app.route('/download')
def download_file():
    filename = request.args.get('filename')
    # Vulnerable file access - direct path manipulation
    try:
        with open(filename, 'r') as f:
            content = f.read()
        return content
    except Exception as e:
        return f"Error: {str(e)}"

# VULNERABILITY: Insecure YAML Parsing
@app.route('/config', methods=['POST'])
def parse_config():
    config_data = request.form.get('config', '')
    # Vulnerable YAML parsing - allows code execution
    try:
        parsed = yaml.load(config_data, Loader=yaml.Loader)
        return str(parsed)
    except Exception as e:
        return f"Error parsing YAML: {str(e)}"

@app.route('/')
def index():
    return '''
        <h1>Vulnerable Flask Application</h1>
        <ul>
            <li><a href="/login">Login</a></li>
            <li><a href="/search?q=test">Search</a></li>
            <li><a href="/ping">Ping Tool</a></li>
        </ul>
    '''

# VULNERABILITY: Debug mode enabled
if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0') 