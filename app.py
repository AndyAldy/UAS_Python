from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
import mysql.connector
from mysql.connector import Error

app = Flask(__name__)
app.secret_key = '12345'

app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''
app.config['MYSQL_DB'] = 'data_mhs'

def get_db_conn():
    """Membuat koneksi ke database MySQL"""
    try:
        conn = mysql.connector.connect(
            host=app.config['MYSQL_HOST'],
            user=app.config['MYSQL_USER'],
            password=app.config['MYSQL_PASSWORD'],
            database=app.config['MYSQL_DB']
        )
        return conn
    except Error as e:
        print(f"Error connecting to MySQL Database: {e}")
        return None

def is_admin():
    """Cek apakah user adalah admin"""
    return 'role' in session and session['role'] == 'admin'

def is_mahasiswa():
    """Cek apakah user adalah mahasiswa"""
    return 'role' in session and session['role'] == 'mahasiswa'

@app.route('/login', methods=['GET', 'POST'])
def login():
    if is_admin():
        return redirect(url_for('manajemen_mahasiswa'))
    if is_mahasiswa():
        return redirect(url_for('dashboard_mahasiswa'))

    error = None
    if request.method == 'POST':
        login_id = request.form['username']
        password = request.form['password']
        
        conn = get_db_conn()
        if conn is None:
            error = "Koneksi ke database gagal."
            return render_template('auth/login.html', error=error)
        
        # Gunakan dictionary=True agar hasil fetch bisa diakses seperti "admin['password']"
        cursor = conn.cursor(dictionary=True)
        
        # Cek admin
        cursor.execute("SELECT * FROM users WHERE username = %s", (login_id,))
        admin = cursor.fetchone()
        
        if admin and check_password_hash(admin['password'], password):
            session['user_id'] = admin['id']
            session['role'] = 'admin'
            session['username'] = admin['nama_lengkap']
            cursor.close()
            conn.close()
            return redirect(url_for('manajemen_mahasiswa'))
        
        # Cek mahasiswa
        cursor.execute("SELECT * FROM mahasiswa WHERE nim = %s", (login_id,))
        mahasiswa = cursor.fetchone()
        
        if mahasiswa and check_password_hash(mahasiswa['password'], password):
            session['user_id'] = mahasiswa['id']
            session['role'] = 'mahasiswa'
            session['username'] = mahasiswa['nama_lengkap']
            cursor.close()
            conn.close()
            return redirect(url_for('dashboard_mahasiswa'))

        cursor.close()
        conn.close()
        error = "NIM/Username atau Password salah."
            
    # REFATOR: Menggunakan path template baru
    return render_template('auth/login.html', error=error)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        nama_lengkap = request.form['nama_lengkap']
        nim = request.form['nim']
        jurusan = request.form['jurusan']
        email = request.form['email']
        password = request.form['password']
        
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        
        conn = None
        cursor = None
        try:
            conn = get_db_conn()
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO mahasiswa (nama_lengkap, nim, jurusan, email, password)
                VALUES (%s, %s, %s, %s, %s)
            """, (nama_lengkap, nim, jurusan, email, hashed_password))
            conn.commit()
            flash("Akun berhasil dibuat! Silakan login menggunakan NIM dan password Anda.", "success")
            return redirect(url_for('login'))
        except Error as e:
            # Mengganti error specific sqlite dengan error general MySQL
            if conn:
                conn.rollback() # Rollback jika terjadi error
            flash(f"NIM '{nim}' sudah terdaftar. Gunakan NIM lain. (Error: {e})", "error")
            # REFATOR: Menggunakan path template baru
            return render_template('auth/register.html')
        finally:
            if cursor:
                cursor.close()
            if conn and conn.is_connected():
                conn.close()

    # REFATOR: Menggunakan path template baru
    return render_template('auth/register.html')

@app.route('/')
def show_beranda():
    if not 'role' in session:
        return redirect(url_for('login'))
    
    if is_admin():
        return redirect(url_for('manajemen_mahasiswa'))
    
    if is_mahasiswa():
        return redirect(url_for('dashboard_mahasiswa'))
        
    return redirect(url_for('login'))

@app.route('/beranda')
def dashboard_mahasiswa():
    if not is_mahasiswa():
        flash("Anda harus login sebagai mahasiswa untuk mengakses halaman ini.", "error")
        return redirect(url_for('login'))
        
    conn = get_db_conn()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM mahasiswa WHERE id = %s", (session['user_id'],))
    mhs_data = cursor.fetchone()
    cursor.close()
    conn.close()
    
    if not mhs_data:
        flash("Data Anda tidak ditemukan.", "error")
        return redirect(url_for('logout'))
        
    # Path template ini sudah benar (tidak di dalam subfolder)
    return render_template('dashboard_mahasiswa.html', mhs=mhs_data, logged_in_user=session['username'])

@app.route('/dashboard')
def manajemen_mahasiswa():
    if not is_admin():
        flash("Anda harus login sebagai admin untuk mengakses halaman ini.", "error")
        return redirect(url_for('login')) 
        
    conn = get_db_conn()
    cursor = conn.cursor(dictionary=True)
    
    cursor.execute("SELECT nama_lengkap, username, email FROM users WHERE id = %s", 
                              (session['user_id'],))
    admin_data = cursor.fetchone()
    
    cursor.execute("SELECT id, nama_lengkap, nim, jurusan, email FROM mahasiswa")
    list_mahasiswa = cursor.fetchall()
    
    cursor.close()
    conn.close()
    
    # REFATOR: Menggunakan path template baru
    return render_template('admin/dashboard.html', mahasiswa=list_mahasiswa, admin=admin_data)

@app.route('/add', methods=['POST'])
def add_mahasiswa():
    if not is_admin():
        return redirect(url_for('login'))
    
    nama_lengkap = request.form['nama_lengkap']
    nim = request.form['nim']
    jurusan = request.form['jurusan']
    email = request.form['email']
    
    conn = None
    cursor = None
    try:
        conn = get_db_conn()
        cursor = conn.cursor()
        hashed_password = "TIDAK_AKTIF"
        
        cursor.execute("""
            INSERT INTO mahasiswa (nama_lengkap, nim, jurusan, email, password)
            VALUES (%s, %s, %s, %s, %s)
        """, (nama_lengkap, nim, jurusan, email, hashed_password))
        conn.commit()
        flash("Data mahasiswa baru berhasil ditambahkan! (Akun non-aktif)", "success")
    except Error as e:
        if conn:
            conn.rollback()
        flash(f"NIM '{nim}' sudah ada di database. Gunakan NIM lain. (Error: {e})", "error")
    finally:
        if cursor:
            cursor.close()
        if conn and conn.is_connected():
            conn.close()
        
    return redirect(url_for('manajemen_mahasiswa'))

@app.route('/edit/<int:mahasiswa_id>', methods=['GET', 'POST'])
def edit_mahasiswa(mahasiswa_id):
    if not is_admin():
        return redirect(url_for('login')) 
    
    conn = get_db_conn()
    
    if request.method == 'POST':
        nama_lengkap = request.form['nama_lengkap']
        nim = request.form['nim']
        jurusan = request.form['jurusan']
        email = request.form['email']
        password_baru = request.form['password_baru']
        
        cursor = conn.cursor()
        try:
            if password_baru:
                hashed_password = generate_password_hash(password_baru, method='pbkdf2:sha256')
                cursor.execute("""
                    UPDATE mahasiswa SET nama_lengkap = %s, nim = %s, jurusan = %s, email = %s, password = %s
                    WHERE id = %s
                """, (nama_lengkap, nim, jurusan, email, hashed_password, mahasiswa_id))
                flash("Data mahasiswa dan password berhasil diupdate.", "success")
            else:
                cursor.execute("""
                    UPDATE mahasiswa SET nama_lengkap = %s, nim = %s, jurusan = %s, email = %s
                    WHERE id = %s
                """, (nama_lengkap, nim, jurusan, email, mahasiswa_id))
                flash("Data mahasiswa berhasil diupdate (password tidak berubah).", "success")

            conn.commit()
        except Error as e:
            if conn:
                conn.rollback()
            flash(f"NIM '{nim}' sudah digunakan oleh mahasiswa lain. (Error: {e})", "error")
        finally:
            cursor.close()
            conn.close()
            
        return redirect(url_for('manajemen_mahasiswa'))
    
    # Bagian GET request
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM mahasiswa WHERE id = %s", (mahasiswa_id,))
    mhs_data = cursor.fetchone()
    cursor.close()
    conn.close()
    
    if not mhs_data:
        flash("Data mahasiswa tidak ditemukan.", "error")
        return redirect(url_for('manajemen_mahasiswa'))
        
    # REFATOR: Menggunakan path template baru
    return render_template('admin/edit_mahasiswa.html', mhs=mhs_data)

@app.route('/delete/<int:mahasiswa_id>', methods=['POST'])
def delete_mahasiswa(mahasiswa_id):
    if not is_admin():
        return redirect(url_for('login')) 
    
    conn = get_db_conn()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM mahasiswa WHERE id = %s", (mahasiswa_id,))
    conn.commit()
    cursor.close()
    conn.close()
    
    flash("Data mahasiswa berhasil dihapus.", "success")
    return redirect(url_for('manajemen_mahasiswa'))

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('role', None) 
    session.pop('username', None)
    flash("Anda telah berhasil logout.", "success")
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)