from __future__ import annotations
import sqlite3
import sys
from datetime import datetime
from pathlib import Path
from . import serial
from .database import get_db_connection
from .logger import setup_logging
def insert_certificate(
    serial_number: int,
    subject: str,
    issuer: str,
    not_before: str,
    not_after: str,
    cert_pem: str,
    status: str = "valid",
    created_at: str | None = None,
    db_path: str | Path = "./pki/micropki.db",
    log_file: str | None = None,
) -> None:
    logger = setup_logging(log_file)
    created_at = created_at or datetime.now().isoformat()
    serial_hex = serial.serial_to_hex(serial_number)
    conn = None
    try:
        conn = get_db_connection(db_path)
        conn.execute('''
            INSERT INTO certificates (
                serial_number, subject, issuer, not_before, not_after, 
                cert_pem, status, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            serial_hex, subject, issuer, not_before, not_after,
            cert_pem, status, created_at
        ))
        conn.commit()
        logger.info("Certificate inserted into database: serial=%s, subject=%s", serial_hex, subject)
    except sqlite3.IntegrityError as e:
        logger.error("Failed to insert certificate (duplicate serial?): %s", e)
        raise
    except sqlite3.Error as e:
        logger.error("Database error during certificate insertion: %s", e)
        raise
    finally:
        if conn:
            conn.close()
def get_certificate_by_serial(
    serial_number: int, 
    db_path: str | Path = "./pki/micropki.db"
) -> dict | None:
    serial_hex = serial.serial_to_hex(serial_number)
    conn = None
    try:
        conn = get_db_connection(db_path)
        row = conn.execute(
            'SELECT * FROM certificates WHERE serial_number = ?', (serial_hex,)
        ).fetchone()
        return dict(row) if row else None
    except sqlite3.Error as e:
        print(f"Database error: {e}", file=sys.stderr)
        return None
    finally:
        if conn:
            conn.close()
def list_certificates(
    status: str | None = None,
    db_path: str | Path = "./pki/micropki.db"
) -> list[dict]:
    conn = None
    try:
        conn = get_db_connection(db_path)
        query = 'SELECT serial_number, subject, not_after, status FROM certificates'
        params = []
        if status:
            query += ' WHERE status = ?'
            params.append(status)
        query += ' ORDER BY created_at DESC'
        rows = conn.execute(query, params).fetchall()
        return [dict(row) for row in rows]
    except sqlite3.Error as e:
        print(f"Database error: {e}", file=sys.stderr)
        return []
    finally:
        if conn:
            conn.close()
def update_certificate_status(serial_number: int, new_status: str,
    revocation_reason: str | None = None,
    revocation_date: str | None = None,
    db_path: str | Path = "./pki/micropki.db") -> None:
    serial_hex = serial.serial_to_hex(serial_number)
    conn = None
    try:
        conn = get_db_connection(db_path)
        conn.execute('''
            UPDATE certificates SET 
                status = ?,
                revocation_reason = ?,
                revocation_date = ?
            WHERE serial_number = ?
        ''', (new_status, revocation_reason, revocation_date, serial_hex))
        conn.commit()
    except sqlite3.Error as e:
        print(f"Database error: {e}", file=sys.stderr)
        raise
    finally:
        if conn:
            conn.close()
def create_server(host, port, db_path, cert_dir, logger, pki_dir=None):
    from http.server import HTTPServer, BaseHTTPRequestHandler
    import json

    class RepoHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/crl" or self.path == "/crl/intermediate.crl.pem":
                p = Path(pki_dir or Path(db_path).parent) / "crl" / "intermediate.crl.pem"
                if p.exists():
                    self._send_file(p, "application/pkix-crl")
                else:
                    self.send_error(404)
            elif self.path == "/ca/root":
                p = Path(cert_dir) / "ca.cert.pem"
                if p.exists(): self._send_file(p, "application/x-pem-file")
                else: self.send_error(404)
            elif self.path == "/ca/intermediate":
                p = Path(cert_dir) / "intermediate.cert.pem"
                if p.exists(): self._send_file(p, "application/x-pem-file")
                else: self.send_error(404)
            elif self.path.startswith("/certificate/"):
                serial_hex = self.path.split("/")[-1].upper()
                try:
                    serial_int = int(serial_hex, 16)
                    row = get_certificate_by_serial(serial_int, db_path=db_path)
                    if row:
                        self.send_response(200)
                        self.send_header("Content-Type", "application/x-pem-file")
                        self.end_headers()
                        self.wfile.write(row["cert_pem"].encode("utf-8"))
                    else:
                        self.send_error(404)
                except ValueError:
                    self.send_error(400)
            else:
                self.send_error(404)

        def _send_file(self, path, content_type):
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("ETag", "test")
            self.send_header("Last-Modified", "test")
            self.send_header("Cache-Control", "max-age=3600")
            content = path.read_bytes()
            self.send_header("Content-Length", len(content))
            self.end_headers()
            self.wfile.write(content)


        def log_message(self, format, *args):
            logger.info(format % args)

    return HTTPServer((host, port), RepoHandler)
