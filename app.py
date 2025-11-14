import os
import json
from datetime import datetime
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, jsonify, send_file
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import sqlite3
from io import BytesIO

app = Flask(__name__)
app.secret_key = 'your-secret-key-change-this-in-production'

# Configuration
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'pdf'}
MAX_FILE_SIZE = 50 * 1024 * 1024  # 50MB

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_FILE_SIZE

# Database initialization
def init_db():
    conn = sqlite3.connect('research_collab.db')
    c = conn.cursor()
    
    # Papers table
    c.execute('''CREATE TABLE IF NOT EXISTS papers
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  title TEXT NOT NULL,
                  filename TEXT NOT NULL,
                  uploaded_by TEXT NOT NULL,
                  upload_date TIMESTAMP,
                  created_at TIMESTAMP)''')
    
    # Researchers table
    c.execute('''CREATE TABLE IF NOT EXISTS researchers
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  email TEXT NOT NULL UNIQUE,
                  password_hash TEXT NOT NULL,
                  access_token TEXT UNIQUE,
                  created_at TIMESTAMP)''')
    
    # Paper access table
    c.execute('''CREATE TABLE IF NOT EXISTS paper_access
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  paper_id INTEGER NOT NULL,
                  researcher_id INTEGER NOT NULL,
                  FOREIGN KEY (paper_id) REFERENCES papers(id),
                  FOREIGN KEY (researcher_id) REFERENCES researchers(id),
                  UNIQUE(paper_id, researcher_id))''')
    
    # Comments table
    c.execute('''CREATE TABLE IF NOT EXISTS comments
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  paper_id INTEGER NOT NULL,
                  researcher_id INTEGER NOT NULL,
                  comment_type TEXT NOT NULL,
                  comment_text TEXT,
                  created_at TIMESTAMP,
                  FOREIGN KEY (paper_id) REFERENCES papers(id),
                  FOREIGN KEY (researcher_id) REFERENCES researchers(id))''')
    
    # Admin user table
    c.execute('''CREATE TABLE IF NOT EXISTS admin_users
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  email TEXT NOT NULL UNIQUE,
                  password_hash TEXT NOT NULL,
                  created_at TIMESTAMP)''')
    
    conn.commit()
    conn.close()

def get_db():
    conn = sqlite3.connect('research_collab.db')
    conn.row_factory = sqlite3.Row
    return conn

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Login required decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'researcher_id' not in session:
            return redirect(url_for('researcher_login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'admin_id' not in session:
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function

# ==================== ADMIN ROUTES ====================

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        conn = get_db()
        c = conn.cursor()
        c.execute('SELECT * FROM admin_users WHERE email = ?', (email,))
        admin = c.fetchone()
        conn.close()
        
        if admin and check_password_hash(admin['password_hash'], password):
            session['admin_id'] = admin['id']
            session['admin_email'] = admin['email']
            return redirect(url_for('admin_dashboard'))
        else:
            return render_template('admin_login.html', error='Invalid credentials')
    
    return render_template('admin_login.html')

@app.route('/admin/setup', methods=['GET', 'POST'])
def admin_setup():
    """Setup page for initial admin creation"""
    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT COUNT(*) as count FROM admin_users')
    admin_count = c.fetchone()['count']
    conn.close()
    
    if admin_count > 0:
        return redirect(url_for('admin_login'))
    
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        conn = get_db()
        c = conn.cursor()
        try:
            c.execute('INSERT INTO admin_users (email, password_hash, created_at) VALUES (?, ?, ?)',
                     (email, generate_password_hash(password), datetime.now()))
            conn.commit()
            conn.close()
            return redirect(url_for('admin_login'))
        except:
            conn.close()
            return render_template('admin_setup.html', error='Email already exists')
    
    return render_template('admin_setup.html')

@app.route('/admin/dashboard')
@admin_login_required
def admin_dashboard():
    conn = get_db()
    c = conn.cursor()
    
    c.execute('SELECT * FROM papers ORDER BY upload_date DESC')
    papers = c.fetchall()
    
    c.execute('SELECT * FROM researchers ORDER BY created_at DESC')
    researchers = c.fetchall()
    
    conn.close()
    
    return render_template('admin_dashboard.html', papers=papers, researchers=researchers)

@app.route('/admin/upload-paper', methods=['POST'])
@admin_login_required
def upload_paper():
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    
    file = request.files['file']
    title = request.form.get('title')
    
    if file.filename == '' or not allowed_file(file.filename):
        return jsonify({'error': 'Invalid file type. Only PDFs allowed.'}), 400
    
    if not title:
        return jsonify({'error': 'Title required'}), 400
    
    filename = secure_filename(file.filename)
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S_')
    filename = timestamp + filename
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(filepath)
    
    conn = get_db()
    c = conn.cursor()
    c.execute('INSERT INTO papers (title, filename, uploaded_by, upload_date, created_at) VALUES (?, ?, ?, ?, ?)',
             (title, filename, session['admin_email'], datetime.now(), datetime.now()))
    paper_id = c.lastrowid
    conn.commit()
    conn.close()
    
    return jsonify({'success': True, 'paper_id': paper_id, 'title': title})

@app.route('/admin/add-researcher', methods=['POST'])
@admin_login_required
def add_researcher():
    email = request.form.get('email')
    password = request.form.get('password')
    paper_ids = request.form.getlist('paper_ids')
    
    if not email or not password:
        return jsonify({'error': 'Email and password required'}), 400
    
    conn = get_db()
    c = conn.cursor()
    
    try:
        c.execute('INSERT INTO researchers (email, password_hash, access_token, created_at) VALUES (?, ?, ?, ?)',
                 (email, generate_password_hash(password), email, datetime.now()))
        researcher_id = c.lastrowid
        
        # Add paper access
        for paper_id in paper_ids:
            c.execute('INSERT INTO paper_access (paper_id, researcher_id) VALUES (?, ?)',
                     (paper_id, researcher_id))
        
        conn.commit()
        conn.close()
        
        return jsonify({'success': True, 'researcher_id': researcher_id, 'email': email})
    except Exception as e:
        conn.close()
        return jsonify({'error': str(e)}), 400

@app.route('/admin/logout')
def admin_logout():
    session.pop('admin_id', None)
    session.pop('admin_email', None)
    return redirect(url_for('admin_login'))

# ==================== RESEARCHER ROUTES ====================

@app.route('/researcher/login', methods=['GET', 'POST'])
def researcher_login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        conn = get_db()
        c = conn.cursor()
        c.execute('SELECT * FROM researchers WHERE email = ?', (email,))
        researcher = c.fetchone()
        conn.close()
        
        if researcher and check_password_hash(researcher['password_hash'], password):
            session['researcher_id'] = researcher['id']
            session['researcher_email'] = researcher['email']
            return redirect(url_for('researcher_dashboard'))
        else:
            return render_template('researcher_login.html', error='Invalid credentials')
    
    return render_template('researcher_login.html')

@app.route('/researcher/dashboard')
@login_required
def researcher_dashboard():
    conn = get_db()
    c = conn.cursor()
    
    c.execute('''SELECT papers.* FROM papers 
                 JOIN paper_access ON papers.id = paper_access.paper_id
                 WHERE paper_access.researcher_id = ?
                 ORDER BY papers.upload_date DESC''', (session['researcher_id'],))
    papers = c.fetchall()
    
    conn.close()
    return render_template('researcher_dashboard.html', papers=papers)

@app.route('/researcher/paper/<int:paper_id>')
@login_required
def view_paper(paper_id):
    conn = get_db()
    c = conn.cursor()
    
    # Check access
    c.execute('''SELECT papers.* FROM papers 
                 JOIN paper_access ON papers.id = paper_access.paper_id
                 WHERE papers.id = ? AND paper_access.researcher_id = ?''',
             (paper_id, session['researcher_id']))
    paper = c.fetchone()
    
    if not paper:
        conn.close()
        return "Access denied", 403
    
    # Get existing comments
    c.execute('SELECT * FROM comments WHERE paper_id = ? AND researcher_id = ? ORDER BY created_at DESC',
             (paper_id, session['researcher_id']))
    comments = c.fetchall()
    
    conn.close()
    
    comment_dict = {}
    for comment in comments:
        comment_dict[comment['comment_type']] = comment['comment_text']
    
    return render_template('researcher_view_paper.html', paper=paper, paper_id=paper_id, comments=comment_dict)

@app.route('/api/paper/<int:paper_id>/pdf')
@login_required
def get_pdf(paper_id):
    conn = get_db()
    c = conn.cursor()
    
    # Check access
    c.execute('''SELECT papers.filename FROM papers 
                 JOIN paper_access ON papers.id = paper_access.paper_id
                 WHERE papers.id = ? AND paper_access.researcher_id = ?''',
             (paper_id, session['researcher_id']))
    result = c.fetchone()
    conn.close()
    
    if not result:
        return "Access denied", 403
    
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], result['filename'])
    return send_file(filepath, mimetype='application/pdf')

@app.route('/api/paper/<int:paper_id>/comments', methods=['POST'])
@login_required
def save_comments(paper_id):
    data = request.get_json()
    
    conn = get_db()
    c = conn.cursor()
    
    # Check access
    c.execute('''SELECT papers.id FROM papers 
                 JOIN paper_access ON papers.id = paper_access.paper_id
                 WHERE papers.id = ? AND paper_access.researcher_id = ?''',
             (paper_id, session['researcher_id']))
    
    if not c.fetchone():
        conn.close()
        return jsonify({'error': 'Access denied'}), 403
    
    # Comment types
    comment_types = ['Typographical Comments', 'Narrative Structure', 'Description of the Methods', 'Tables & Figures']
    
    for comment_type in comment_types:
        comment_text = data.get(comment_type, '').strip()
        
        # Delete existing comment if empty
        if not comment_text:
            c.execute('DELETE FROM comments WHERE paper_id = ? AND researcher_id = ? AND comment_type = ?',
                     (paper_id, session['researcher_id'], comment_type))
        else:
            # Check if comment exists
            c.execute('SELECT id FROM comments WHERE paper_id = ? AND researcher_id = ? AND comment_type = ?',
                     (paper_id, session['researcher_id'], comment_type))
            existing = c.fetchone()
            
            if existing:
                c.execute('UPDATE comments SET comment_text = ? WHERE id = ?',
                         (comment_text, existing['id']))
            else:
                c.execute('INSERT INTO comments (paper_id, researcher_id, comment_type, comment_text, created_at) VALUES (?, ?, ?, ?, ?)',
                         (paper_id, session['researcher_id'], comment_type, comment_text, datetime.now()))
    
    conn.commit()
    conn.close()
    
    return jsonify({'success': True})

@app.route('/researcher/logout')
def researcher_logout():
    session.pop('researcher_id', None)
    session.pop('researcher_email', None)
    return redirect(url_for('researcher_login'))

# ==================== HOME ROUTE ====================

@app.route('/')
def index():
    return redirect(url_for('admin_login'))

# Error handling
@app.errorhandler(413)
def request_entity_too_large(error):
    return jsonify({'error': 'File too large. Max 50MB'}), 413

if __name__ == '__main__':
    init_db()
    app.run(debug=True, port=5000)
