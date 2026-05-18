import os
from sqlalchemy import create_engine, MetaData, Table, Column, Integer, String
from werkzeug.security import generate_password_hash

# ----------------------
# DB configuration
# ----------------------
DB_USER = "root"
DB_PASS = ""  # your MySQL root password if any
DB_HOST = "localhost"
DB_NAME = "mini_project_db"

DB_URI = f"mysql+mysqlconnector://{DB_USER}:{DB_PASS}@{DB_HOST}/{DB_NAME}"
engine = create_engine(DB_URI, echo=True, future=True)
metadata = MetaData()

# ----------------------
# Users table
# ----------------------
users_table = Table(
    "users",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("username", String(50), unique=True, nullable=False),
    Column("email", String(100), unique=True, nullable=False),
    Column("password", String(255), nullable=False)
)

# ----------------------
# Insert test user
# ----------------------
username = "testuser"
email = "test@example.com"
password = "mypassword"

hashed_password = generate_password_hash(password)

try:
    with engine.connect() as conn:
        with conn.begin():
            conn.execute(users_table.insert().values(
                username=username,
                email=email,
                password=hashed_password
            ))
    print("✅ Test user inserted successfully!")
except Exception as e:
    print("❌ Error inserting test user:", e)
