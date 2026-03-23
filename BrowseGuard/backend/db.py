# db.py — all database operations
import mysql.connector
from mysql.connector import Error

DB_CONFIG = {
    "host": "localhost",
    "user": "root",
    "password": "",        # change this if your MySQL root has a password
    "database": "browseguard"
}


def get_connection():
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        return conn
    except Error as e:
        print(f"Database connection error: {e}")
        return None


def log_visit(url, score, reasons):
    conn = get_connection()
    if not conn:
        return
    try:
        cursor = conn.cursor()
        reasons_str = " | ".join(reasons) if reasons else ""
        flagged = 1 if len(reasons) > 0 else 0
        cursor.execute(
            "INSERT INTO visits (url, score, reasons, flagged) VALUES (%s, %s, %s, %s)",
            (url, score, reasons_str, flagged)
        )
        conn.commit()
    except Error as e:
        print(f"Error saving visit: {e}")
    finally:
        cursor.close()
        conn.close()


def get_history(limit=10000):
    """Returns up to `limit` visits. Default is 10000 (effectively all)."""
    conn = get_connection()
    if not conn:
        return []
    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute(
            """
            SELECT id, url, score, reasons, flagged, created_at
            FROM visits
            ORDER BY created_at DESC
            LIMIT %s
            """,
            (limit,)
        )
        rows = cursor.fetchall()
        for row in rows:
            row["created_at"] = str(row["created_at"])
            row["reasons"] = row["reasons"].split(" | ") if row["reasons"] else []
        return rows
    except Error as e:
        print(f"Error fetching history: {e}")
        return []
    finally:
        cursor.close()
        conn.close()


def get_stats():
    conn = get_connection()
    if not conn:
        return {"avg_score": 100, "total": 0, "flagged": 0, "safe": 0}
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM visits")
        total = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM visits WHERE flagged = 1")
        flagged = cursor.fetchone()[0]
        cursor.execute("SELECT AVG(score) FROM visits")
        avg_result = cursor.fetchone()[0]
        avg_score = round(avg_result) if avg_result else 100
        return {"avg_score": avg_score, "total": total, "flagged": flagged, "safe": total - flagged}
    except Error as e:
        print(f"Error fetching stats: {e}")
        return {"avg_score": 100, "total": 0, "flagged": 0, "safe": 0}
    finally:
        cursor.close()
        conn.close()