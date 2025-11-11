import mysql.connector
from mysql.connector import Error
from werkzeug.security import generate_password_hash

# --- KONFIGURASI MYSQL (SAMAKAN DENGAN app.py) ---
DB_CONFIG = {
    'host': 'localhost',
    'user': 'root',
    'password': '', # Kosongkan jika XAMPP tidak pakai password
    'database': 'data_mhs' # Nama database yang Anda buat
}
# --------------------------------------------------

def init_db():
    try:
        # Terhubung ke database
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor()

        # 1. Hapus tabel lama jika ada
        print("Menghapus tabel lama (jika ada)...")
        cursor.execute("DROP TABLE IF EXISTS users")
        cursor.execute("DROP TABLE IF EXISTS mahasiswa")

        # 2. Buat tabel 'users' (Admin) - Sintaks MySQL
        print("Membuat tabel 'users' untuk admin...")
        cursor.execute("""
        CREATE TABLE users (
            id INT PRIMARY KEY AUTO_INCREMENT,
            username VARCHAR(255) NOT NULL UNIQUE, 
            password TEXT NOT NULL,
            nama_lengkap VARCHAR(255) NOT NULL,
            email VARCHAR(255), 
            role VARCHAR(50) NOT NULL DEFAULT 'admin'
        )
        """)

        # 3. Buat tabel 'mahasiswa' - Sintaks MySQL
        print("Membuat tabel 'mahasiswa'...")
        cursor.execute("""
        CREATE TABLE mahasiswa (
            id INT PRIMARY KEY AUTO_INCREMENT,
            nama_lengkap VARCHAR(255) NOT NULL,
            nim VARCHAR(255) NOT NULL UNIQUE,
            jurusan VARCHAR(255) NOT NULL,
            email VARCHAR(255),
            password TEXT NOT NULL 
        )
        """)

        # 4. Masukkan data admin default
        print("Memasukkan data admin default (admin/admin123)...")
        admin_pass_hash = generate_password_hash('admin123', method='pbkdf2:sha256')
        cursor.execute("""
        INSERT INTO users (username, password, nama_lengkap, email, role) 
        VALUES (%s, %s, %s, %s, 'admin')
        """, ('admin', admin_pass_hash, 'Administrator', 'admin@sistem.com'))

        # 5. Masukkan data contoh mahasiswa
        print("Memasukkan data contoh mahasiswa (pass: mahasiswa123)...")
        mhs_pass_hash = generate_password_hash('mahasiswa123', method='pbkdf2:sha256')

        contoh_mahasiswa = [
            ('Andy Aldyansyah', '10123001', 'Teknik Informatika', 'andy@kampus.com', mhs_pass_hash),
            ('Angel Threesilia', '10123002', 'Farmasi', 'angel@kampus.com', mhs_pass_hash),
            ('Citra Lestari', '10223001', 'Desain Grafis', 'citra@kampus.com', mhs_pass_hash)
        ]
        
        # Gunakan %s untuk placeholder
        cursor.executemany("""
        INSERT INTO mahasiswa (nama_lengkap, nim, jurusan, email, password) 
        VALUES (%s, %s, %s, %s, %s)
        """, contoh_mahasiswa)


        conn.commit()
        print(f"Database '{DB_CONFIG['database']}' berhasil dibuat ulang.")
        print("Silakan jalankan 'app.py'.")

    except Error as e:
        print(f"Error: {e}")
        if 'conn' in locals() and conn.is_connected():
            conn.rollback()
    finally:
        if 'conn' in locals() and conn.is_connected():
            cursor.close()
            conn.close()

if __name__ == '__main__':
    init_db()