from __future__ import annotations
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path
import fastapi
from fastapi import FastAPI, HTTPException, Request, status
from fastapi.responses import PlainTextResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from . import crypto_utils
from . import ca as ca_module
from .database import get_db_connection
from .logger import setup_logging
from .repository import get_certificate_by_serial, list_certificates

app = FastAPI(title="Megacrypto PKI Repository", version="1.0")  # изменено название
logger = None
CERT_DIR = Path("./pki/certs")

CA_CONFIG = {
    "ca_cert_path": None,
    "ca_key_path": None,
    "ca_passphrase": None,
    "db_path": "./pki/micropki.db",
    "out_dir": "./pki/certs",
}

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def init_server(
    log_file: str | None = None,
    cert_dir: str | Path = "./pki/certs",
    ca_cert: str | None = None,
    ca_key: str | None = None,
    ca_pass_file: str | None = None,
    db_path: str = "./pki/micropki.db",
    rate_limit: float = 0,
    rate_burst: int = 10,
):
    global logger
    logger = setup_logging(log_file)
    global CERT_DIR
    CERT_DIR = Path(cert_dir)
    if not CERT_DIR.exists():
        logger.error("Certificate directory does not exist: %s", CERT_DIR)
        raise FileNotFoundError(f"Certificate directory not found: {CERT_DIR}")

    CA_CONFIG["db_path"] = db_path
    CA_CONFIG["out_dir"] = str(cert_dir)

    if ca_cert and ca_key and ca_pass_file:
        CA_CONFIG["ca_cert_path"] = ca_cert
        CA_CONFIG["ca_key_path"] = ca_key
        CA_CONFIG["ca_passphrase"] = crypto_utils.load_passphrase(ca_pass_file)
        logger.info("CA signing enabled for /request-cert endpoint")
    else:
        logger.warning("CA signing NOT configured. POST /request-cert will be unavailable.")

    if rate_limit > 0:
        from .ratelimit import create_rate_limit_middleware
        middleware_fn = create_rate_limit_middleware(rate_limit, rate_burst)
        app.middleware("http")(middleware_fn)
        logger.info("Rate limiting enabled: %s req/s, burst=%d", rate_limit, rate_burst)

    logger.info("Repository server initialised. Serving certificates from %s", CERT_DIR)


@app.middleware("http")
async def log_requests(request: Request, call_next):
    start_time = datetime.now()
    response = await call_next(request)
    duration = (datetime.now() - start_time).total_seconds() * 1000
    if logger:
        logger.info("[HTTP] %s %s %s %d %dms",
                    request.client.host, request.method, request.url.path,
                    response.status_code, duration)
    return response


@app.get("/certificate/{serial_hex}")
async def get_certificate(serial_hex: str):
    serial_hex = serial_hex.upper()
    try:
        serial_number = int(serial_hex, 16)
        cert_data = get_certificate_by_serial(serial_number, db_path=CA_CONFIG["db_path"])
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid serial number format. Must be hex.")
    except Exception as e:
        if logger: logger.error("Database error in /certificate: %s", e)
        raise HTTPException(status_code=500, detail="Internal server error")

    if not cert_data:
        raise HTTPException(status_code=404, detail="Certificate not found")
    if cert_data["status"] == "revoked":
        raise HTTPException(status_code=410, detail="Certificate revoked")
    return PlainTextResponse(content=cert_data["cert_pem"], media_type="application/x-pem-file")


@app.get("/ca/{level}")
async def get_ca_certificate(level: str):
    if level not in ["root", "intermediate"]:
        raise HTTPException(status_code=400, detail="Invalid level. Use 'root' or 'intermediate'")
    filename = "ca.cert.pem" if level == "root" else "intermediate.cert.pem"
    cert_path = CERT_DIR / filename
    if not cert_path.exists():
        raise HTTPException(status_code=404, detail="CA certificate not found")
    try:
        cert_pem = cert_path.read_text(encoding="utf-8")
        return PlainTextResponse(content=cert_pem, media_type="application/x-pem-file")
    except Exception as e:
        if logger: logger.error("Error reading CA certificate file %s: %s", cert_path, e)
        raise HTTPException(status_code=500, detail="Error reading CA certificate")


@app.get("/crl")
async def get_crl(ca: str = "intermediate"):
    if ca not in ["root", "intermediate"]:
        raise HTTPException(status_code=400, detail="Invalid CA. Use 'root' or 'intermediate'")
    filename = f"{ca}.crl.pem"
    crl_path = CERT_DIR.parent / "crl" / filename
    if not crl_path.exists():
        raise HTTPException(status_code=404, detail="CRL not found")
    try:
        crl_pem = crl_path.read_text(encoding="utf-8")
        stat = crl_path.stat()
        headers = {
            "Content-Type": "application/pkix-crl",
            "Last-Modified": datetime.fromtimestamp(stat.st_mtime, timezone.utc).strftime('%a, %d %b %Y %H:%M:%S GMT'),
            "Cache-Control": "max-age=3600"
        }
        return PlainTextResponse(content=crl_pem, media_type="application/pkix-crl", headers=headers)
    except Exception as e:
        if logger: logger.error("Error reading CRL file %s: %s", crl_path, e)
        raise HTTPException(status_code=500, detail="Error reading CRL file")


class CertRequest(BaseModel):
    csr_pem: str
    template: str = "server"


@app.post("/request-cert", status_code=201)
async def request_cert(req: CertRequest, request: Request):
    if not CA_CONFIG["ca_cert_path"]:
        raise HTTPException(status_code=503, detail="CA signing not configured on this server")

    client_ip = request.client.host if request.client else "unknown"
    if logger:
        logger.info("[API] Certificate request from %s, template=%s", client_ip, req.template)
        logger.warning("[API] No authentication on /request-cert endpoint (demo mode)")

    try:
        cert_pem = ca_module.issue_end_entity(
            ca_cert_path=CA_CONFIG["ca_cert_path"],
            ca_key_path=CA_CONFIG["ca_key_path"],
            ca_passphrase=CA_CONFIG["ca_passphrase"],
            template=req.template,
            subject="",
            san_strings=[],
            out_dir=CA_CONFIG["out_dir"],
            validity_days=365,
            csr_pem=req.csr_pem,
            db_path=CA_CONFIG["db_path"],
        )
    except ValueError as e:
        if logger: logger.error("[API] Certificate request rejected: %s", e)
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        if logger: logger.error("[API] Certificate issuance failed: %s", e)
        raise HTTPException(status_code=500, detail=f"Issuance failed: {e}")

    if logger:
        logger.info("[API] Certificate issued successfully for request from %s", client_ip)
    return PlainTextResponse(content=cert_pem, status_code=201, media_type="application/x-pem-file")


@app.get("/")
async def root():
    return {"message": "Megacrypto PKI Repository is running", "status": "ok"}  # изменено название