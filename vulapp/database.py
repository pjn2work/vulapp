"""Database initialization and management."""
import sqlite3
import os
from vulapp.config import DATABASE, USERNAME, PASSWORD


def init_db():
    """Initialize the database with test data."""
    if os.path.exists(DATABASE):
        os.remove(DATABASE)  # Reset for clean demo
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, bio TEXT)")
        cursor.execute(f"INSERT INTO users (username, password, bio) VALUES ('{USERNAME}', '{PASSWORD}', 'Administrator account')")
        cursor.execute("INSERT INTO users (username, password, bio) VALUES ('guest', 'guest123', 'Regular guest user')")
        conn.commit()
