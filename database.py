# database.py

import sqlite3
import os
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE_PATH = os.path.join(BASE_DIR, "alerts.db")


def get_connection():
    connection = sqlite3.connect(DATABASE_PATH, check_same_thread=False)
    connection.row_factory = sqlite3.Row
    return connection


def initialize_database():
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            time TEXT NOT NULL,
            alert_type TEXT NOT NULL,
            source_ip TEXT NOT NULL,
            destination_ip TEXT NOT NULL,
            message TEXT NOT NULL,
            severity TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'Open'
        )
    """)

    connection.commit()
    connection.close()


def add_alert(alert_type, source_ip, destination_ip, message, severity):
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        INSERT INTO alerts (
            time,
            alert_type,
            source_ip,
            destination_ip,
            message,
            severity,
            status
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        alert_type,
        source_ip,
        destination_ip,
        message,
        severity,
        "Open"
    ))

    connection.commit()
    alert_id = cursor.lastrowid
    connection.close()

    return alert_id


def get_all_alerts():
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT
            id,
            time,
            alert_type AS type,
            source_ip,
            destination_ip,
            message,
            severity,
            status
        FROM alerts
        ORDER BY id DESC
    """)

    rows = cursor.fetchall()
    connection.close()

    return [dict(row) for row in rows]


def clear_all_alerts():
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("DELETE FROM alerts")

    connection.commit()
    connection.close()


def resolve_alert(alert_id):
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        UPDATE alerts
        SET status = 'Resolved'
        WHERE id = ?
    """, (alert_id,))

    connection.commit()
    changed_rows = cursor.rowcount
    connection.close()

    return changed_rows > 0