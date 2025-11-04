# Impor 'session', 'secret_key', 'flash' dan 'werkzeug'
from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3

app = Flask(__name__)
app.secret_key = 'ini_kunci_rahasia_kamu_angel_bisa_diisi_apa_saja'
DB_NAME = 'database.db'

def get_db_conn():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row 
    return conn

# --- FUNGSI UNTUK ADMIN ---
def is_admin():
    """Cek apakah user adalah admin"""
    return 'user_role' in session and session['user_role'] == 'admin'

# --- ROUTE LOGIN (HALAMAN UTAMA) ---
@app.route('/', methods=['GET', 'POST'])
def login():
    if 'user_username' in session:
        return redirect(url_for('show_beranda')) 

    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db_conn()
        user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        conn.close()
        
        if user and check_password_hash(user['password'], password):
            session['user_username'] = user['username']
            session['user_role'] = user['role'] 
            return redirect(url_for('show_beranda'))
        else:
            error = "Username atau Password salah."
            
    return render_template('user/login.html', error=error)

# --- ROUTE REGISTER BARU ---
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        nama_lengkap = request.form['nama_lengkap']
        bio = request.form['bio']
        
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        
        try:
            conn = get_db_conn()
            conn.execute("""
                INSERT INTO users (username, password, nama_lengkap, bio, role)
                VALUES (?, ?, ?, ?, 'user')
            """, (username, hashed_password, nama_lengkap, bio))
            conn.commit()
            conn.close()
            
            flash("Akun berhasil dibuat! Silakan login.", "success")
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            error = "Username sudah digunakan. Coba yang lain."
            return render_template('user/register.html', error=error)

    return render_template('user/register.html')

# --- ROUTE BERANDA (ROUTER) ---
@app.route('/beranda')
def show_beranda():
    if 'user_username' not in session:
        return redirect(url_for('login'))
    
    if is_admin():
        # PENYESUAIAN: Admin sekarang melihat halaman sambutan
        return render_template('admin/beranda_admin.html', logged_in_user=session['user_username'])
    else:
        # User biasa melihat beranda user
        conn = get_db_conn()
        user_data = conn.execute("SELECT * FROM users WHERE username = ?", (session['user_username'],)).fetchone()
        conn.close()
        return render_template('user/beranda_user.html', user=user_data)

# --- ROUTE BARU KHUSUS MANAJEMEN ADMIN ---
@app.route('/admin/manajemen')
def manajemen_user():
    if not is_admin():
        return redirect(url_for('login')) # Hanya admin
        
    conn = get_db_conn()
    users_list = conn.execute("SELECT id, username, nama_lengkap, role FROM users").fetchall()
    conn.close()
    # Menampilkan halaman CRUD
    return render_template('admin/manajemen_user.html', users=users_list, logged_in_user=session['user_username'])

# --- ROUTE CRUD (Admin Only) ---

@app.route('/admin/add', methods=['POST'])
def add_user():
    if not is_admin():
        return redirect(url_for('login'))
        
    # (Logika 'add_user' kamu tetap sama)
    username = request.form['username']
    password = request.form['password']
    nama_lengkap = request.form['nama_lengkap']
    bio = request.form['bio']
    role = request.form['role']
    hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
    
    conn = get_db_conn()
    conn.execute("""
        INSERT INTO users (username, password, nama_lengkap, bio, role)
        VALUES (?, ?, ?, ?, ?)
    """, (username, hashed_password, nama_lengkap, bio, role))
    conn.commit()
    conn.close()
    
    flash("User baru berhasil ditambahkan!", "success")
    # PENYESUAIAN: Redirect ke halaman manajemen, bukan beranda
    return redirect(url_for('manajemen_user'))

@app.route('/admin/edit/<int:user_id>', methods=['GET', 'POST'])
def edit_user(user_id):
    if not is_admin():
        return redirect(url_for('login')) 
    
    conn = get_db_conn()
    
    if request.method == 'POST':
        # (Logika 'edit_user' POST kamu tetap sama)
        nama_lengkap = request.form['nama_lengkap']
        bio = request.form['bio']
        role = request.form['role']
        
        conn.execute("""
            UPDATE users SET nama_lengkap = ?, bio = ?, role = ?
            WHERE id = ?
        """, (nama_lengkap, bio, role, user_id))
        
        password = request.form['password']
        if password:
            hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
            conn.execute("UPDATE users SET password = ? WHERE id = ?", (hashed_password, user_id))
            
        conn.commit()
        conn.close()
        flash("Data user berhasil diupdate.", "success")
        # PENYESUAIAN: Redirect ke halaman manajemen, bukan beranda
        return redirect(url_for('manajemen_user'))
    
    # (Logika 'edit_user' GET kamu tetap sama)
    user_data = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    conn.close()
    if not user_data:
        return redirect(url_for('manajemen_user'))
        
    return render_template('admin/edit_user.html', user=user_data)

@app.route('/admin/delete/<int:user_id>', methods=['POST'])
def delete_user(user_id):
    if not is_admin():
        return redirect(url_for('login')) 
    
    # (Logika 'delete_user' kamu tetap sama)
    conn = get_db_conn()
    admin_user = conn.execute("SELECT * FROM users WHERE username = ?", (session['user_username'],)).fetchone()
    if admin_user['id'] == user_id:
        flash("Admin tidak bisa menghapus akunnya sendiri!", "error")
        return redirect(url_for('manajemen_user'))

    conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()
    
    flash("User berhasil dihapus.", "success")
    # PENYESUAIAN: Redirect ke halaman manajemen, bukan beranda
    return redirect(url_for('manajemen_user'))

# --- Route Lama (masih berfungsi, tapi terkunci) ---
@app.route('/profile')
def profile():
    if 'user_username' not in session:
        return redirect(url_for('login'))
    return render_template('user/profile.html')

@app.route('/profile/<username>')
def show_user_profile(username):
    if 'user_username' not in session:
        return redirect(url_for('login'))
        
    conn = get_db_conn()
    user_data = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    conn.close()
    
    if user_data:
        return render_template('user/user_profile.html', user=user_data)
    else:
        return render_template('user/404_user.html', username=username), 404

# --- LOGOUT ---
@app.route('/logout')
def logout():
    session.pop('user_username', None)
    session.pop('user_role', None) 
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)

