from __future__ import annotations
import sqlite3
from pathlib import Path
from .logger import setup_logging
def get_db_connection(db_path: str | Path) -> sqlite3.Connection:
    db_path = Path(db_path)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row  
    return conn
def init_database(db_path: str | Path, log_file: str | None = None) -> None:
    logger = setup_logging(log_file)
    conn = None
    try:
        conn = get_db_connection(db_path)
        conn.execute('''
            CREATE TABLE IF NOT EXISTS certificates (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                serial_number TEXT UNIQUE NOT NULL,
                subject TEXT NOT NULL,
                issuer TEXT NOT NULL,
                not_before TEXT NOT NULL,
                not_after TEXT NOT NULL,
                cert_pem TEXT NOT NULL,
                status TEXT NOT NULL,
                revocation_reason TEXT,
                revocation_date TEXT,
                created_at TEXT NOT NULL
            )
        ''')
        conn.execute('CREATE INDEX IF NOT EXISTS idx_serial ON certificates(serial_number)')
        conn.execute('CREATE INDEX IF NOT EXISTS idx_status ON certificates(status)')
        conn.execute('''
            CREATE TABLE IF NOT EXISTS crl_metadata (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ca_subject TEXT NOT NULL,
                crl_number INTEGER NOT NULL,
                last_generated TEXT NOT NULL,
                next_update TEXT NOT NULL,
                crl_path TEXT NOT NULL
            )
        ''')
        conn.execute('CREATE UNIQUE INDEX IF NOT EXISTS idx_ca_subject ON crl_metadata(ca_subject)')
        conn.execute('''
            CREATE TABLE IF NOT EXISTS compromised_keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                public_key_hash TEXT UNIQUE NOT NULL,
                certificate_serial TEXT NOT NULL,
                compromise_date TEXT NOT NULL,
                compromise_reason TEXT NOT NULL,
                FOREIGN KEY (certificate_serial) REFERENCES certificates(serial_number)
            )
        ''')
        conn.commit()
        logger.info("Database initialised successfully at %s", db_path)
    except sqlite3.Error as e:
        logger.error("Database initialisation failed: %s", e)
        raise
    finally:
        if conn:
            conn.close()
def set_certificate_revoked(db_path: str | Path, serial_number_hex: str, reason: str, revocation_date: str) -> bool:
    conn = get_db_connection(db_path)
    try:
        cur = conn.cursor()
        cur.execute("SELECT status FROM certificates WHERE serial_number = ?", (serial_number_hex,))
        row = cur.fetchone()
        if not row:
            return False
        if row["status"] == "revoked":
            return False
        cur.execute('''
            UPDATE certificates
            SET status = 'revoked', revocation_reason = ?, revocation_date = ?
            WHERE serial_number = ?
        ''', (reason, revocation_date, serial_number_hex))
        conn.commit()
        return True
    finally:
        conn.close()
def get_revoked_certificates_by_issuer(db_path: str | Path, issuer: str) -> list[dict]:
    conn = get_db_connection(db_path)
    try:
        cur = conn.cursor()
        cur.execute('''
            SELECT serial_number, revocation_reason, revocation_date
            FROM certificates
            WHERE issuer = ? AND status = 'revoked'
        ''', (issuer,))
        return [dict(row) for row in cur.fetchall()]
    finally:
        conn.close()
def get_crl_metadata(db_path: str | Path, ca_subject: str) -> dict | None:
    conn = get_db_connection(db_path)
    try:
        cur = conn.cursor()
        cur.execute('''
            SELECT crl_number, last_generated, next_update, crl_path
            FROM crl_metadata
            WHERE ca_subject = ?
        ''', (ca_subject,))
        row = cur.fetchone()
        return dict(row) if row else None
    finally:
        conn.close()
def update_crl_metadata(db_path: str | Path, ca_subject: str, crl_number: int, 
                        last_generated: str, next_update: str, crl_path: str) -> None:
    conn = get_db_connection(db_path)
    try:
        cur = conn.cursor()
        cur.execute("SELECT id FROM crl_metadata WHERE ca_subject = ?", (ca_subject,))
        if cur.fetchone():
            cur.execute('''
                UPDATE crl_metadata
                SET crl_number = ?, last_generated = ?, next_update = ?, crl_path = ?
                WHERE ca_subject = ?
            ''', (crl_number, last_generated, next_update, crl_path, ca_subject))
        else:
            cur.execute('''
                INSERT INTO crl_metadata (ca_subject, crl_number, last_generated, next_update, crl_path)
                VALUES (?, ?, ?, ?, ?)
            ''', (ca_subject, crl_number, last_generated, next_update, crl_path))
        conn.commit()
    finally:
        conn.close()

def insert_compromised_key(db_path: str | Path, public_key_hash: str,
                           certificate_serial: str, compromise_date: str,
                           compromise_reason: str) -> None:
    """Insert a compromised key record into the database."""
    conn = get_db_connection(db_path)
    try:
        conn.execute('''
            INSERT OR IGNORE INTO compromised_keys
                (public_key_hash, certificate_serial, compromise_date, compromise_reason)
            VALUES (?, ?, ?, ?)
        ''', (public_key_hash, certificate_serial, compromise_date, compromise_reason))
        conn.commit()
    finally:
        conn.close()

def is_key_hash_compromised(db_path: str | Path, public_key_hash: str) -> bool:
    """Return True if the given public key hash is in the compromised_keys table."""
    conn = get_db_connection(db_path)
    try:
        row = conn.execute(
            'SELECT 1 FROM compromised_keys WHERE public_key_hash = ?',
            (public_key_hash,)
        ).fetchone()
        return row is not None
    except Exception:
        return False
    finally:
        conn.close()

def get_cert_pem_by_serial(db_path: str | Path, serial_hex: str) -> str | None:
    """Retrieve cert PEM by serial (hex string)."""
    conn = get_db_connection(db_path)
    try:
        row = conn.execute(
            'SELECT cert_pem FROM certificates WHERE serial_number = ?',
            (serial_hex,)
        ).fetchone()
        return row["cert_pem"] if row else None
    except Exception:
        return None
    finally:
        conn.close()

def get_certificate_by_serial(db_path: str | Path, serial_hex: str) -> dict | None:
    from . import repository
    try:
        serial_number = int(serial_hex, 16)
        return repository.get_certificate_by_serial(serial_number, db_path=db_path)
    except ValueError:
        return None
def list_certificates(db_path: str | Path) -> list[dict]:
    from . import repository
    rows = repository.list_certificates(db_path=db_path)
    for r in rows:
        if "serial_hex" not in r and "serial_number" in r:
            r["serial_hex"] = r["serial_number"]
    return rows
# Alias used by some modules
init_db = init_database
