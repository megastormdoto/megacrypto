from __future__ import annotations
import base64
from datetime import datetime
from pathlib import Path
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from . import crypto_utils
from . import ocsp
from .logger import setup_logging

app = FastAPI(title="Megacrypto PKI OCSP Responder", version="1.0")  # изменено название

CONFIG = {
    "db_path": "",
    "responder_cert": None,
    "responder_key": None,
    "issuer_cert": None,
    "logger": None
}

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def init_ocsp_server(
    db_path: str,
    responder_cert_path: str,
    responder_key_path: str,
    issuer_cert_path: str,
    log_file: str | None = None,
    rate_limit: float = 0,
    rate_burst: int = 10,
):
    CONFIG["logger"] = setup_logging(log_file)
    CONFIG["db_path"] = db_path
    try:
        CONFIG["responder_cert"] = crypto_utils.load_certificate_pem(responder_cert_path)
        CONFIG["responder_key"] = crypto_utils.load_private_key_encrypted(responder_key_path, None)
        CONFIG["issuer_cert"] = crypto_utils.load_certificate_pem(issuer_cert_path)
    except Exception as e:
        CONFIG["logger"].error("Failed to load certificates/keys for OCSP: %s", e)
        raise RuntimeError(f"OCSP Init failed: {e}")

    if rate_limit > 0:
        from .ratelimit import create_rate_limit_middleware
        middleware_fn = create_rate_limit_middleware(rate_limit, rate_burst)
        app.middleware("http")(middleware_fn)
        CONFIG["logger"].info("Rate limiting enabled: %s req/s, burst=%d", rate_limit, rate_burst)

    CONFIG["logger"].info("OCSP responder initialised and ready.")


@app.middleware("http")
async def log_requests(request: Request, call_next):
    start_time = datetime.now()
    response = await call_next(request)
    duration = (datetime.now() - start_time).total_seconds() * 1000
    if CONFIG["logger"]:
        CONFIG["logger"].info("[OCSP] %s %s %s %d %dms",
                    request.client.host, request.method, request.url.path,
                    response.status_code, duration)
    return response


@app.get("/{base64_req}")
async def get_ocsp(base64_req: str):
    try:
        req_der = base64.urlsafe_b64decode(base64_req)
        return _process_request(req_der)
    except Exception as e:
        if CONFIG["logger"]: CONFIG["logger"].error("GET OCSP failed: %s", e)
        raise HTTPException(status_code=400, detail="Invalid Base64 or OCSP Request")


@app.post("/")
async def post_ocsp(request: Request):
    if "application/ocsp-request" not in request.headers.get("content-type", ""):
        raise HTTPException(status_code=415, detail="Unsupported Media Type")
    req_der = await request.body()
    return _process_request(req_der)


def _process_request(req_der: bytes) -> Response:
    resp_der = ocsp.process_ocsp_request(
        req_der,
        CONFIG["responder_cert"],
        CONFIG["responder_key"],
        CONFIG["issuer_cert"],
        CONFIG["db_path"],
        CONFIG["logger"]
    )
    return Response(content=resp_der, media_type="application/ocsp-response")


@app.get("/")
async def ocsp_health():
    return {"status": "Megacrypto OCSP responder is running"}  # изменено название