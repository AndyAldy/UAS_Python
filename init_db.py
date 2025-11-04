import sqlite3
from werkzeug.security import generate_password_hash

DB_NAME = 'database.db'

conn = sqlite3.connect(DB_NAME)
cursor = conn.cursor()

cursor.execute("DROP TABLE IF EXISTS users")

cursor.execute("""
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    
    -- PENYESUAIAN DI SINI:
    -- Kata 'UNIQUE' sudah dihapus.
    username TEXT NOT NULL, 
    
    password TEXT NOT NULL,
    nama_lengkap TEXT NOT NULL,
    bio TEXT,
    role TEXT NOT NULL DEFAULT 'user'
)
""")

# Data contoh tetap sama
users_data = [
    ('admin', generate_password_hash('admin123', method='pbkdf2:sha256'), 'Administrator', 'Saya adalah admin.', 'admin'),
    ('Andy', generate_password_hash('andy123', method='pbkdf2:sha256'), 'Andy Aldyansyah', 'Penggemar Programming dan kopi.', 'user'),
    ('Angel', generate_password_hash('angel123', method='pbkdf2:sha256'), 'Angel Threesilia', 'Sedang belajar obat-obat an.', 'user'),
    ('Citra', generate_password_hash('citra123', method='pbkdf2:sha256'), 'Citra Lestari', 'Desainer grafis dan ilustrator.', 'user'),
    
    # (Contoh data duplikat yang SEKARANG BISA dimasukkan)
    ('Andy', generate_password_hash('andy456', method='pbkdf2:sha256'), 'Andy yang Lain', 'Saya Andy yang kedua.', 'user')
]

cursor.executemany("""
INSERT INTO users (username, password, nama_lengkap, bio, role) 
VALUES (?, ?, ?, ?, ?)
""", users_data)

conn.commit()
conn.close()

print(f"Database '{DB_NAME}' berhasil dibuat TANPA username unik.")
print("PERINGATAN: Aplikasi login kemungkinan besar akan error.")
