from __future__ import annotations
import argparse
import sys
from pathlib import Path
from . import ca
from . import crl as crl_module
from . import database
from . import crypto_utils
from . import database
from . import logger as log_module
from . import repository
from . import serial

def _validate_file_exists(parser, path, label):
    if not path or not Path(path).is_file():
        parser.error(f"{label} must exist and be readable: {path}")


def _validate_passphrase_file(parser, path, label="--passphrase-file"):
    if not path:
        parser.error(f"{label} is required")
    p = Path(path)
    if not p.exists():
        parser.error(f"{label} must exist: {path}")
    if not p.is_file():
        parser.error(f"{label} is not a file: {path}")
    try:
        p.read_bytes()
    except OSError:
        parser.error(f"Cannot read {label}: {path}")


def _validate_subject(parser, args):
    subject = getattr(args, "subject", None)
    if not (subject or "").strip():
        parser.error("--subject is required and must be non-empty")
    try:
        from . import certificates
        certificates.parse_subject_dn(subject)
    except ValueError as e:
        parser.error(f"Invalid --subject DN: {e}")


def _validate_out_dir(parser, out_dir):
    out = Path(out_dir)
    if out.exists() and not out.is_dir():
        parser.error(f"--out-dir must be a directory: {out_dir}")
    try:
        out.mkdir(parents=True, exist_ok=True)
        test = out / ".micropki_write_test"
        test.write_text("")
        test.unlink()
    except OSError:
        parser.error(f"--out-dir must be writable: {out_dir}")


def _default_db_path_for_out_dir(out_dir: str) -> str:
    out = Path(out_dir)
    if out.name == "certs":
        return str(out.parent / "micropki.db")
    return str(out / "micropki.db")


def _validate_key_type_size(parser, key_type: str, key_size: int) -> None:
    key_type = (key_type or "").lower()
    if key_type == "rsa" and key_size not in (2048, 3072, 4096):
        parser.error("--key-size must be 2048, 3072 or 4096 for RSA")
    if key_type == "ecc" and key_size not in (256, 384):
        parser.error("--key-size must be 256 or 384 for ECC")


def cmd_ca_init(args) -> int:
    parser = getattr(args, "_parser", argparse.ArgumentParser())
    log = log_module.setup_logging(getattr(args, "log_file", None))

    _validate_subject(parser, args)
    key_type = args.key_type.lower()
    if key_type == "rsa" and args.key_size != 4096:
        log.error("--key-size must be 4096 for RSA")
        parser.error("--key-size must be 4096 for RSA")
    if key_type == "ecc" and args.key_size != 384:
        log.error("--key-size must be 384 for ECC")
        parser.error("--key-size must be 384 for ECC")

    _validate_passphrase_file(parser, args.passphrase_file)
    out_dir = args.out_dir or "./pki"
    _validate_out_dir(parser, out_dir)

    if not isinstance(args.validity_days, int) or args.validity_days <= 0:
        parser.error("--validity-days must be a positive integer")

    try:
        passphrase = crypto_utils.load_passphrase(args.passphrase_file)
    except Exception as e:
        log.error("Cannot read passphrase file: %s", e)
        print("Error: could not read passphrase file.", file=sys.stderr)
        return 1

    try:
        ca.init_root_ca(
            subject=args.subject.strip(),
            key_type=key_type,
            key_size=args.key_size,
            passphrase=passphrase,
            out_dir=out_dir,
            validity_days=args.validity_days,
            db_path=args.db_path,
            log_file=args.log_file,
            force=getattr(args, "force", False),
        )
    except FileExistsError as e:
        print(str(e), file=sys.stderr)
        return 1
    except Exception as e:
        log.exception("CA init failed")
        print(f"Error: {e}", file=sys.stderr)
        return 1
    return 0


def cmd_ca_issue_intermediate(args) -> int:
    parser = getattr(args, "_parser", argparse.ArgumentParser())
    log = log_module.setup_logging(getattr(args, "log_file", None))

    _validate_file_exists(parser, args.root_cert, "--root-cert")
    _validate_file_exists(parser, args.root_key, "--root-key")
    _validate_passphrase_file(parser, args.root_pass_file, "--root-pass-file")
    _validate_passphrase_file(parser, args.passphrase_file, "--passphrase-file")
    _validate_subject(parser, args)
    _validate_key_type_size(parser, args.key_type, args.key_size)

    if args.pathlen < 0:
        parser.error("--pathlen must be >= 0")

    out_dir = args.out_dir or "./pki"
    _validate_out_dir(parser, out_dir)

    try:
        root_pass = crypto_utils.load_passphrase(args.root_pass_file)
        inter_pass = crypto_utils.load_passphrase(args.passphrase_file)
    except Exception as e:
        log.error("Cannot read passphrase file: %s", e)
        print("Error: could not read passphrase file.", file=sys.stderr)
        return 1

    try:
        ca.issue_intermediate_ca(
            root_cert_path=args.root_cert,
            root_key_path=args.root_key,
            root_passphrase=root_pass,
            subject=args.subject.strip(),
            key_type=args.key_type.lower(),
            key_size=args.key_size,
            passphrase=inter_pass,
            out_dir=out_dir,
            validity_days=args.validity_days,
            pathlen=args.pathlen,
            db_path=args.db_path,
            log_file=args.log_file,
            force=getattr(args, "force", False),
        )
    except FileExistsError as e:
        print(str(e), file=sys.stderr)
        return 1
    except Exception as e:
        log.exception("issue-intermediate failed")
        print(f"Error: {e}", file=sys.stderr)
        return 1
    return 0


def cmd_ca_issue_cert(args) -> int:
    parser = getattr(args, "_parser", argparse.ArgumentParser())
    log = log_module.setup_logging(getattr(args, "log_file", None))

    _validate_file_exists(parser, args.ca_cert, "--ca-cert")
    _validate_file_exists(parser, args.ca_key, "--ca-key")
    _validate_passphrase_file(parser, args.ca_pass_file, "--ca-pass-file")
    _validate_subject(parser, args)

    out_dir = args.out_dir or "./pki/certs"
    _validate_out_dir(parser, out_dir)

    try:
        ca_pass = crypto_utils.load_passphrase(args.ca_pass_file)
    except Exception as e:
        log.error("Cannot read passphrase file: %s", e)
        print("Error: could not read passphrase file.", file=sys.stderr)
        return 1

    try:
        ca.issue_end_entity(
            ca_cert_path=args.ca_cert,
            ca_key_path=args.ca_key,
            ca_passphrase=ca_pass,
            template=args.template,
            subject=args.subject.strip(),
            san_strings=args.san or [],
            out_dir=out_dir,
            validity_days=args.validity_days,
            csr_path=getattr(args, "csr", None),
            db_path=args.db_path,
            log_file=args.log_file,
        )
    except ValueError as e:
        log.error("Validation error: %s", e)
        print(f"Error: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        log.exception("issue-cert failed")
        print(f"Error: {e}", file=sys.stderr)
        return 1
    return 0


def cmd_ca_list_certs(args) -> int:
    log = log_module.setup_logging(getattr(args, "log_file", None))
    try:
        status_filter = args.status if args.status in ("valid", "revoked") else None
        rows = repository.list_certificates(status=status_filter, db_path=args.db_path)
        if args.status == "expired":
            from datetime import datetime, timezone
            now = datetime.now(timezone.utc)
            rows = [r for r in rows if datetime.fromisoformat(r["not_after"].replace("Z", "+00:00")) < now]
    except Exception as e:
        log.error("Database query failed: %s", e)
        print(f"Error: {e}", file=sys.stderr)
        return 1

    if args.format == "json":
        import json
        output = []
        for r in rows:
            d = dict(r)
            if "serial_hex" not in d and "serial_number" in d:
                d["serial_hex"] = d["serial_number"]
            output.append(d)
        print(json.dumps(output, ensure_ascii=False, indent=2))
        return 0

    if args.format == "csv":
        print("serial,subject,expiration,status")
        for r in rows:
            sn = r.get('serial_hex', r.get('serial_number', ''))
            print(f"{sn},{r['subject']},{r['not_after']},{r['status']}")
        return 0

    print(f"{'SERIAL':<20} {'STATUS':<8} {'EXPIRES':<22} SUBJECT")
    print("-" * 95)
    for r in rows:
        sn = r.get('serial_hex', r.get('serial_number', ''))
        print(f"{sn:<20} {r['status']:<8} {r['not_after']:<22} {r['subject']}")
    return 0


def cmd_ca_show_cert(args) -> int:
    log = log_module.setup_logging(getattr(args, "log_file", None))
    serial_hex = args.serial.strip()
    try:
        serial_number = int(serial_hex, 16)
    except ValueError:
        print("Error: serial must be hex", file=sys.stderr)
        return 1

    try:
        row = repository.get_certificate_by_serial(serial_number, db_path=args.db_path)
    except Exception as e:
        log.error("Database query failed: %s", e)
        print(f"Error: {e}", file=sys.stderr)
        return 1

    if row is None:
        print("Error: certificate not found", file=sys.stderr)
        return 1

    log.info("Certificate retrieval via ca show-cert: serial=%s", serial_hex.upper())
    print(row["cert_pem"])
    return 0


def cmd_ca_verify(args) -> int:
    cert_path = getattr(args, "cert", None)
    if not cert_path or not Path(cert_path).exists():
        log = log_module.setup_logging(getattr(args, "log_file", None))
        log.error("Certificate file not found: %s", cert_path)
        print(f"Error: certificate file not found: {cert_path}", file=sys.stderr)
        return 1

    try:
        ca.verify_certificate(cert_path, log_file=args.log_file)
        return 0
    except Exception as e:
        print(f"Verification failed: {e}", file=sys.stderr)
        return 1


def cmd_ca_verify_chain(args) -> int:
    log = log_module.setup_logging(getattr(args, "log_file", None))
    from . import chain as chain_module

    for p in [args.leaf, args.root] + (args.intermediate or []):
        if not Path(p).is_file():
            log.error("File not found: %s", p)
            print(f"Error: file not found: {p}", file=sys.stderr)
            return 1

    try:
        leaf = crypto_utils.load_certificate_pem(args.leaf)
        root = crypto_utils.load_certificate_pem(args.root)
        intermediates = [crypto_utils.load_certificate_pem(p) for p in (args.intermediate or [])]
        chain_module.validate_chain(leaf, intermediates, root)
        log.info("Chain validation succeeded: leaf=%s", args.leaf)
        print("Chain validation: OK")
        return 0
    except Exception as e:
        log.error("Chain validation failed: %s", e)
        print(f"Chain validation failed: {e}", file=sys.stderr)
        return 1


def cmd_ca_revoke(args) -> int:
    log = log_module.setup_logging(getattr(args, "log_file", None))
    from . import revocation

    try:
        if not args.force:
            ans = input(f"Are you sure you want to revoke {args.serial}? [y/N]: ")
            if ans.lower() != 'y':
                print("Aborted.")
                return 0

        success = revocation.revoke(args.db_path, args.serial, args.reason, log_file=args.log_file)
        if success:
            print(f"Revoked {args.serial}")
        else:
            print(f"Certificate {args.serial} is already revoked.", file=sys.stderr)
        return 0
    except Exception as e:
        log.error("Revocation failed: %s", e)
        print(f"Error: {e}", file=sys.stderr)
        return 1


def cmd_ca_gen_crl(args) -> int:
    log = log_module.setup_logging(getattr(args, "log_file", None))
    from . import crl
    parser = getattr(args, "_parser", argparse.ArgumentParser())

    ca_cert = getattr(args, "ca_cert", None)
    ca_key = getattr(args, "ca_key", None)
    ca_name = getattr(args, "ca", None)
    out_dir = getattr(args, "out_dir", "./pki")

    if ca_name == "root":
        if not ca_cert:
            ca_cert = str(Path(out_dir) / "certs" / "ca.cert.pem")
        if not ca_key:
            ca_key = str(Path(out_dir) / "private" / "ca.key.pem")
    elif ca_name == "intermediate":
        if not ca_cert:
            ca_cert = str(Path(out_dir) / "certs" / "intermediate.cert.pem")
        if not ca_key:
            ca_key = str(Path(out_dir) / "private" / "intermediate.key.pem")

    _validate_file_exists(parser, ca_cert, "--ca-cert")
    _validate_file_exists(parser, ca_key, "--ca-key")
    _validate_passphrase_file(parser, args.ca_pass_file, "--ca-pass-file")

    try:
        ca_pass = crypto_utils.load_passphrase(args.ca_pass_file)
    except Exception as e:
        log.error("Cannot read passphrase file: %s", e)
        print("Error: could not read passphrase file.", file=sys.stderr)
        return 1

    try:
        out_path = crl.generate_crl(
            ca_cert_path=ca_cert,
            ca_key_path=ca_key,
            ca_passphrase=ca_pass,
            out_dir=out_dir,
            db_path=args.db_path,
            next_update_days=args.next_update,
            out_file=getattr(args, "out_file", None),
            log_file=args.log_file
        )
        print(f"CRL generated at {out_path}")
        return 0
    except Exception as e:
        log.error("CRL generation failed: %s", e)
        print(f"Error: {e}", file=sys.stderr)
        return 1


def cmd_ca_check_revoked(args) -> int:
    log = log_module.setup_logging(getattr(args, "log_file", None))
    from . import revocation

    try:
        status_info = revocation.check_revocation(args.db_path, args.serial)
        print(f"status={status_info['status']}")
        if status_info['status'] == 'revoked':
            print(f"reason={status_info['reason']}")
            print(f"date={status_info['date']}")

        crl_path = getattr(args, "crl", None)
        if crl_path:
            from cryptography import x509
            with open(crl_path, "rb") as f:
                crl_obj = x509.load_pem_x509_crl(f.read())
            serial_int = int(args.serial, 16)
            is_in_crl = any(r.serial_number == serial_int for r in crl_obj)
            print(f"crl_contains_serial={'yes' if is_in_crl else 'no'}")

        return 0
    except Exception as e:
        log.error("Check revocation failed: %s", e)
        print(f"Error: {e}", file=sys.stderr)
        return 1


def cmd_ca_compromise(args) -> int:
    log = log_module.setup_logging(getattr(args, "log_file", None))
    from . import compromise

    if not args.force:
        try:
            ans = input(f"Simulate compromise for {args.cert}? [y/N]: ")
            if ans.lower() != 'y':
                print("Aborted.")
                return 0
        except EOFError:
            print("Aborted.")
            return 0

    try:
        result = compromise.mark_compromised(
            db_path=args.db_path,
            cert_path=args.cert,
            reason=args.reason,
            audit_dir=str(Path(args.db_path).parent / "audit") if args.db_path else "./pki/audit",
            ca_cert_path=getattr(args, "ca_cert", None),
            ca_key_path=getattr(args, "ca_key", None),
            ca_pass_file=getattr(args, "ca_pass_file", None),
            out_dir=getattr(args, "out_dir", None),
        )
        print(f"Certificate {result['serial']} marked as compromised.")
        print(f"Public key hash: {result['public_key_hash']}")
        if result['revoked']:
            print("Certificate has been revoked with reason keyCompromise.")
        else:
            print("Certificate was already revoked.")
        return 0
    except Exception as e:
        log.exception("Compromise simulation failed")
        print(f"Error: {e}", file=sys.stderr)
        return 1


def cmd_ocsp_serve(args) -> int:
    import uvicorn
    from .ocsp_responder import init_ocsp_server, app

    try:
        init_ocsp_server(
            db_path=args.db_path,
            responder_cert_path=args.responder_cert,
            responder_key_path=args.responder_key,
            issuer_cert_path=args.ca_cert,
            log_file=args.log_file,
            rate_limit=getattr(args, "rate_limit", 0),
            rate_burst=getattr(args, "rate_burst", 10),
        )
        sys.exit(uvicorn.run(app, host=args.host, port=args.port, log_level="info"))
    except Exception as e:
        print(f"Error starting OCSP server: {e}", file=sys.stderr)
        return 1


def cmd_db_init(args):
    from . import database
    db_path = getattr(args, "db_path", "./pki/micropki.db")
    log_file = getattr(args, "log_file", None)
    log = log_module.setup_logging(log_file)

    try:
        database.init_database(db_path)
        log.info("Database initialized at %s", db_path)
        return 0
    except Exception as e:
        log.error("Database initialization failed: %s", e)
        print(f"Error: {e}", file=sys.stderr)
        return 1


def cmd_repo_serve(args):
    import uvicorn
    from .repo import init_server, app

    init_server(
        log_file=args.log_file,
        cert_dir=args.cert_dir,
        ca_cert=getattr(args, "ca_cert", None),
        ca_key=getattr(args, "ca_key", None),
        ca_pass_file=getattr(args, "ca_pass_file", None),
        db_path=args.db_path,
        rate_limit=getattr(args, "rate_limit", 0),
        rate_burst=getattr(args, "rate_burst", 10),
    )
    sys.exit(uvicorn.run(app, host=args.host, port=args.port, log_level="info"))


def cmd_client_gen_csr(args) -> int:
    log = log_module.setup_logging(getattr(args, "log_file", None))
    from . import client as client_module

    try:
        client_module.generate_csr(
            subject=args.subject,
            key_type=args.key_type,
            key_size=args.key_size,
            san_strings=getattr(args, "san", None),
            out_key=args.out_key,
            out_csr=args.out_csr,
            log_file=args.log_file,
        )
        return 0
    except Exception as e:
        log.error("gen-csr failed: %s", e)
        print(f"Error: {e}", file=sys.stderr)
        return 1


def cmd_client_request_cert(args) -> int:
    log = log_module.setup_logging(getattr(args, "log_file", None))
    from . import client as client_module

    try:
        client_module.request_certificate(
            csr_path=args.csr,
            template=args.template,
            ca_url=args.ca_url,
            out_cert=args.out_cert,
            log_file=args.log_file,
        )
        return 0
    except Exception as e:
        log.error("request-cert failed: %s", e)
        print(f"Error: {e}", file=sys.stderr)
        return 1


def cmd_client_validate(args) -> int:
    log = log_module.setup_logging(getattr(args, "log_file", None))
    from . import client as client_module

    try:
        result = client_module.validate_certificate(
            cert_path=args.cert,
            untrusted_paths=getattr(args, "untrusted", None),
            trusted_path=args.trusted,
            crl_source=getattr(args, "crl", None),
            use_ocsp=getattr(args, "ocsp", False),
            ocsp_url=getattr(args, "ocsp_url", None),
            mode=args.mode,
            validation_time=getattr(args, "validation_time", None),
            output_format=getattr(args, "format", "table"),
            log_file=args.log_file,
        )
        return 0 if result.passed else 1
    except Exception as e:
        log.error("validate failed: %s", e)
        print(f"Error: {e}", file=sys.stderr)
        return 1


def cmd_client_check_status(args) -> int:
    log = log_module.setup_logging(getattr(args, "log_file", None))
    from . import client as client_module

    try:
        result = client_module.check_status(
            cert_path=args.cert,
            ca_cert_path=args.ca_cert,
            crl_source=getattr(args, "crl", None),
            ocsp_url=getattr(args, "ocsp_url", None),
            log_file=args.log_file,
        )
        return 0 if result.status == "good" else 1
    except Exception as e:
        log.error("check-status failed: %s", e)
        print(f"Error: {e}", file=sys.stderr)
        return 1


def cmd_ca_issue_ocsp_cert(args) -> int:
    log = log_module.setup_logging(getattr(args, "log_file", None))
    _validate_passphrase_file(args._parser, args.ca_pass_file, "--ca-pass-file")
    ca_pass = crypto_utils.load_passphrase(args.ca_pass_file)
    from . import ca

    try:
        ca.issue_end_entity(
            ca_cert_path=args.ca_cert,
            ca_key_path=args.ca_key,
            ca_passphrase=ca_pass,
            template="ocsp",
            subject=args.subject,
            san_strings=getattr(args, "san", []),
            out_dir=args.out_dir,
            validity_days=args.validity_days,
            db_path=args.db_path,
            log_file=args.log_file,
        )
        return 0
    except Exception as e:
        log.error("issue-ocsp-cert failed: %s", getattr(e, "message", str(e)))
        print(f"Error: {e}", file=sys.stderr)
        return 1


def cmd_audit_query(args) -> int:
    from . import audit as audit_module
    import json as json_mod

    log_path = getattr(args, "log_file_path", "./pki/audit/audit.log")
    entries = audit_module.query_log(
        log_path=log_path,
        from_ts=getattr(args, "from_ts", None),
        to_ts=getattr(args, "to_ts", None),
        level=getattr(args, "level", None),
        operation=getattr(args, "operation", None),
        serial=getattr(args, "serial", None),
    )

    if getattr(args, "verify", False):
        chain_path = str(Path(log_path).parent / "chain.dat")
        ok, bad_idx = audit_module.verify_log(log_path, chain_path)
        if not ok:
            print(f"INTEGRITY FAILURE: tampered at entry {bad_idx}", file=sys.stderr)
            return 1
        print("Integrity check: OK")

    fmt = getattr(args, "format", "table")
    if fmt == "json":
        print(json_mod.dumps(entries, ensure_ascii=False, indent=2))
    elif fmt == "csv":
        print("timestamp,level,operation,status,message")
        for e in entries:
            print(f"{e.get('timestamp','')},{e.get('level','')},{e.get('operation','')},{e.get('status','')},{e.get('message','')}")
    else:
        print(f"{'TIMESTAMP':<28} {'LEVEL':<8} {'OPERATION':<22} {'STATUS':<8} MESSAGE")
        print("-" * 110)
        for e in entries:
            print(f"{e.get('timestamp',''):<28} {e.get('level',''):<8} {e.get('operation',''):<22} {e.get('status',''):<8} {e.get('message','')}")
    return 0


def cmd_audit_verify(args) -> int:
    from . import audit as audit_module

    log_path = getattr(args, "log_file_path", "./pki/audit/audit.log")
    chain_path = getattr(args, "chain_file", "./pki/audit/chain.dat")

    ok, bad_idx = audit_module.verify_log(log_path, chain_path)
    if ok:
        print("Audit log integrity: OK")
        return 0
    else:
        print(f"INTEGRITY FAILURE: first corrupted entry at index {bad_idx}", file=sys.stderr)
        return 1


def cmd_demo_run(args) -> int:
    try:
        import runpy
        demo_script = Path(__file__).parent.parent / "demo" / "demo.py"
        if not demo_script.exists():
            print(f"Error: demo script not found at {demo_script}", file=sys.stderr)
            return 1
        runpy.run_path(str(demo_script), run_name="__main__")
        return 0
    except Exception as e:
        print(f"Demo failed: {e}", file=sys.stderr)
        return 1


def main() -> None:
    print()
    print("=" * 64)
    print("  P K I   S Y S T E M   -   C U S T O M   B U I L D")
    print("=" * 64)
    print("-" * 64)
    print()

    parser = argparse.ArgumentParser(prog="micropki", description="MicroPKI - minimal PKI")
    subparsers = parser.add_subparsers(dest="command", help="Commands")

    ca_parser = subparsers.add_parser("ca", help="CA operations")
    ca_sub = ca_parser.add_subparsers(dest="ca_command")

    db_parser = subparsers.add_parser("db", help="Database operations")
    db_sub = db_parser.add_subparsers(dest="db_command")

    repo_parser = subparsers.add_parser("repo", help="Repository server operations")
    repo_sub = repo_parser.add_subparsers(dest="repo_command")

    ocsp_parser = subparsers.add_parser("ocsp", help="OCSP responder functions")
    ocsp_sub = ocsp_parser.add_subparsers(dest="ocsp_command")

    audit_parser = subparsers.add_parser("audit", help="Audit log operations")
    audit_sub = audit_parser.add_subparsers(dest="audit_command")

    demo_parser = subparsers.add_parser("demo", help="Demo operations")
    demo_sub = demo_parser.add_subparsers(dest="demo_command")

    p_demo_run = demo_sub.add_parser("run", help="Run the full demo scenario")
    p_demo_run.set_defaults(_run=cmd_demo_run)

    p_init = db_sub.add_parser("init", help="Initialise the certificate database")
    p_init.set_defaults(_parser=p_init, _run=cmd_db_init)
    p_init.add_argument("--db-path", default="./pki/micropki.db", help="Path to the SQLite database")
    p_init.add_argument("--log-file", default=None)

    client_parser = subparsers.add_parser("client", help="Client tools")
    client_sub = client_parser.add_subparsers(dest="client_command")

    p_serve = repo_sub.add_parser("serve", help="Start the repository HTTP server")
    p_serve.set_defaults(_parser=p_serve, _run=cmd_repo_serve)
    p_serve.add_argument("--host", default="127.0.0.1", help="Bind address")
    p_serve.add_argument("--port", type=int, default=8080, help="TCP port")
    p_serve.add_argument("--db-path", default="./pki/micropki.db", help="Path to the SQLite database")
    p_serve.add_argument("--cert-dir", default="./pki/certs", help="Directory containing PEM certificates")
    p_serve.add_argument("--ca-cert", default=None, help="CA cert PEM for /request-cert")
    p_serve.add_argument("--ca-key", default=None, help="CA key PEM for /request-cert")
    p_serve.add_argument("--ca-pass-file", default=None, help="CA passphrase file for /request-cert")
    p_serve.add_argument("--rate-limit", type=float, default=0, help="Requests/sec per client IP (0=disabled)")
    p_serve.add_argument("--rate-burst", type=int, default=10, help="Burst allowance")
    p_serve.add_argument("--log-file", default=None)

    p = ca_sub.add_parser("init", help="Create self-signed Root CA")
    p.set_defaults(_parser=p, _run=cmd_ca_init)
    p.add_argument("--subject", required=True)
    p.add_argument("--key-type", default="rsa", choices=["rsa", "ecc"])
    p.add_argument("--key-size", type=int, default=4096)
    p.add_argument("--passphrase-file", required=True)
    p.add_argument("--out-dir", default="./pki")
    p.add_argument("--validity-days", type=int, default=3650)
    p.add_argument("--log-file", default=None)
    p.add_argument("--force", action="store_true")
    p.add_argument("--db-path", default="./pki/micropki.db", help="SQLite DB path (default: ./pki/micropki.db)")

    p = ca_sub.add_parser("issue-intermediate", help="Create Intermediate CA signed by Root")
    p.set_defaults(_parser=p, _run=cmd_ca_issue_intermediate)
    p.add_argument("--root-cert", required=True, help="Root CA cert PEM")
    p.add_argument("--root-key", required=True, help="Root CA encrypted key PEM")
    p.add_argument("--root-pass-file", required=True, help="Root CA passphrase file")
    p.add_argument("--subject", required=True)
    p.add_argument("--key-type", default="rsa", choices=["rsa", "ecc"])
    p.add_argument("--key-size", type=int, default=4096)
    p.add_argument("--passphrase-file", required=True, help="Intermediate CA passphrase file")
    p.add_argument("--out-dir", default="./pki")
    p.add_argument("--validity-days", type=int, default=1825)
    p.add_argument("--pathlen", type=int, default=0)
    p.add_argument("--log-file", default=None)
    p.add_argument("--force", action="store_true")
    p.add_argument("--db-path", default="./pki/micropki.db", help="SQLite DB path (default: ./pki/micropki.db)")

    p = ca_sub.add_parser("issue-cert", help="Issue end-entity certificate")
    p.set_defaults(_parser=p, _run=cmd_ca_issue_cert)
    p.add_argument("--ca-cert", required=True, help="Issuing CA cert PEM")
    p.add_argument("--ca-key", required=True, help="Issuing CA encrypted key PEM")
    p.add_argument("--ca-pass-file", required=True, help="Issuing CA passphrase file")
    p.add_argument("--template", required=True, choices=["server", "client", "code_signing", "vpn"])
    p.add_argument("--subject", required=True)
    p.add_argument("--san", action="append", help="SAN entry (e.g. dns:example.com, ip:1.2.3.4, email:a@b.c)")
    p.add_argument("--out-dir", default="./pki/certs")
    p.add_argument("--validity-days", type=int, default=365)
    p.add_argument("--csr", default=None, help="External CSR PEM (optional)")
    p.add_argument("--log-file", default=None)
    p.add_argument("--db-path", default=None, help="SQLite DB path (default: inferred from --out-dir)")

    p = ca_sub.add_parser("verify", help="Verify certificate (self-signed)")
    p.set_defaults(_run=cmd_ca_verify)
    p.add_argument("--cert", required=True)
    p.add_argument("--log-file", default=None)

    p = ca_sub.add_parser("list-certs", help="List certificates from database")
    p.set_defaults(_run=cmd_ca_list_certs)
    p.add_argument("--db-path", default="./pki/micropki.db")
    p.add_argument("--status", choices=["valid", "revoked", "expired"], default=None)
    p.add_argument("--format", choices=["table", "json", "csv"], default="table")
    p.add_argument("--log-file", default=None)

    p = ca_sub.add_parser("show-cert", help="Show certificate PEM by serial")
    p.set_defaults(_run=cmd_ca_show_cert)
    p.add_argument("serial")
    p.add_argument("--db-path", default="./pki/micropki.db")
    p.add_argument("--log-file", default=None)

    p = ca_sub.add_parser("verify-chain", help="Validate full certificate chain")
    p.set_defaults(_run=cmd_ca_verify_chain)
    p.add_argument("--leaf", required=True, help="Leaf certificate PEM")
    p.add_argument("--intermediate", action="append", help="Intermediate cert(s) PEM")
    p.add_argument("--root", required=True, help="Root CA cert PEM")
    p.add_argument("--log-file", default=None)

    p = ca_sub.add_parser("revoke", help="Revoke a certificate")
    p.set_defaults(_run=cmd_ca_revoke)
    p.add_argument("serial", help="Serial number of the certificate to revoke (hex)")
    p.add_argument("--reason", default="unspecified", help="Revocation reason code")
    p.add_argument("--db-path", default="./pki/micropki.db", help="Path to DB")
    p.add_argument("--force", action="store_true", help="Skip confirmation")
    p.add_argument("--out-dir", default=None, help="PKI output directory (optional, for compatibility)")
    p.add_argument("--log-file", default=None)

    p = ca_sub.add_parser("gen-crl", help="Generate CRL for a CA")
    p.set_defaults(_parser=p, _run=cmd_ca_gen_crl)
    p.add_argument("--ca", choices=["root", "intermediate"], help="CA type to generate CRL for")
    p.add_argument("--ca-cert", help="CA cert PEM")
    p.add_argument("--ca-key", help="CA encrypted key PEM")
    p.add_argument("--ca-pass-file", required=True, help="CA passphrase file")
    p.add_argument("--out-dir", default="./pki")
    p.add_argument("--out-file", default=None, help="Custom output file for CRL")
    p.add_argument("--next-update", type=int, default=7, help="Days until next update")
    p.add_argument("--db-path", default="./pki/micropki.db")
    p.add_argument("--log-file", default=None)

    p = ca_sub.add_parser("issue-ocsp-cert", help="Issue OCSP responder certificate")
    p.set_defaults(_parser=p, _run=cmd_ca_issue_ocsp_cert)
    p.add_argument("--ca-cert", required=True, help="CA cert PEM")
    p.add_argument("--ca-key", required=True, help="CA encrypted key PEM")
    p.add_argument("--ca-pass-file", required=True, help="CA passphrase file")
    p.add_argument("--subject", required=True, help="Subject DN")
    p.add_argument("--key-type", choices=["rsa", "ecc"], default="rsa")
    p.add_argument("--key-size", type=int, default=2048)
    p.add_argument("--san", action="append", help="SAN (e.g. dns:ocsp.example.com)")
    p.add_argument("--out-dir", default="./pki/certs")
    p.add_argument("--validity-days", type=int, default=365)
    p.add_argument("--db-path", default="./pki/micropki.db")
    p.add_argument("--log-file", default=None)

    p = ca_sub.add_parser("check-revoked", help="Check revocation status of a certificate")
    p.set_defaults(_run=cmd_ca_check_revoked)
    p.add_argument("serial", help="Serial number of the certificate (hex)")
    p.add_argument("--db-path", default="./pki/micropki.db")
    p.add_argument("--crl", help="Optional CRL PEM to check serial against")
    p.add_argument("--log-file", default=None)

    p = ca_sub.add_parser("compromise", help="Simulate private key compromise")
    p.set_defaults(_parser=p, _run=cmd_ca_compromise)
    p.add_argument("--cert", required=True, help="Path to certificate of compromised key")
    p.add_argument("--reason", default="keyCompromise", help="Reason code")
    p.add_argument("--force", action="store_true", help="Skip confirmation")
    p.add_argument("--db-path", default="./pki/micropki.db")
    p.add_argument("--ca-cert", default=None, help="CA cert for emergency CRL")
    p.add_argument("--ca-key", default=None, help="CA key for emergency CRL")
    p.add_argument("--ca-pass-file", default=None, help="CA pass file for emergency CRL")
    p.add_argument("--out-dir", default="./pki", help="PKI output directory")
    p.add_argument("--log-file", default=None)

    p = ocsp_sub.add_parser("serve", help="Start the OCSP responder")
    p.set_defaults(_run=cmd_ocsp_serve)
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8081)
    p.add_argument("--db-path", default="./pki/micropki.db")
    p.add_argument("--responder-cert", required=True, help="OCSP cert PEM")
    p.add_argument("--responder-key", required=True, help="OCSP key PEM")
    p.add_argument("--ca-cert", required=True, help="Issuer CA cert PEM")
    p.add_argument("--cache-ttl", type=int, default=60, help="Cache TTL (unused)")
    p.add_argument("--rate-limit", type=float, default=0, help="Requests/sec per IP (0=disabled)")
    p.add_argument("--rate-burst", type=int, default=10, help="Burst allowance")
    p.add_argument("--log-file", default=None)

    p = audit_sub.add_parser("query", help="Query audit log entries")
    p.set_defaults(_run=cmd_audit_query)
    p.add_argument("--log-file-path", default="./pki/audit/audit.log", help="Audit log file")
    p.add_argument("--from", dest="from_ts", default=None, help="Start timestamp (ISO 8601)")
    p.add_argument("--to", dest="to_ts", default=None, help="End timestamp (ISO 8601)")
    p.add_argument("--level", default=None, choices=["INFO", "WARNING", "ERROR", "AUDIT"])
    p.add_argument("--operation", default=None, help="Filter by operation type")
    p.add_argument("--serial", default=None, help="Filter by certificate serial")
    p.add_argument("--format", choices=["table", "json", "csv"], default="table")
    p.add_argument("--verify", action="store_true", help="Verify hash chain integrity")

    p = audit_sub.add_parser("verify", help="Verify audit log integrity")
    p.set_defaults(_run=cmd_audit_verify)
    p.add_argument("--log-file-path", default="./pki/audit/audit.log", help="Audit log file")
    p.add_argument("--chain-file", default="./pki/audit/chain.dat", help="Hash chain file")

    p = client_sub.add_parser("gen-csr", help="Generate private key and CSR")
    p.set_defaults(_run=cmd_client_gen_csr)
    p.add_argument("--subject", required=True, help="Subject DN")
    p.add_argument("--key-type", choices=["rsa", "ecc"], default="rsa")
    p.add_argument("--key-size", type=int, default=2048)
    p.add_argument("--san", action="append", help="SAN (e.g. dns:app.example.com)")
    p.add_argument("--out-key", default="./key.pem", help="Output key file")
    p.add_argument("--out-csr", default="./request.csr.pem", help="Output CSR file")
    p.add_argument("--log-file", default=None)

    p = client_sub.add_parser("request-cert", help="Submit CSR and receive certificate")
    p.set_defaults(_run=cmd_client_request_cert)
    p.add_argument("--csr", required=True, help="Path to CSR PEM file")
    p.add_argument("--template", required=True, choices=["server", "client", "code_signing"])
    p.add_argument("--ca-url", required=True, help="Base URL of the repository")
    p.add_argument("--out-cert", default="./cert.pem", help="Output certificate file")
    p.add_argument("--log-file", default=None)

    p = client_sub.add_parser("validate", help="Validate certificate chain")
    p.set_defaults(_run=cmd_client_validate)
    p.add_argument("--cert", required=True, help="Leaf certificate PEM")
    p.add_argument("--untrusted", action="append", help="Intermediate cert(s) PEM")
    p.add_argument("--trusted", default="./pki/certs/ca.cert.pem", help="Trusted root cert PEM")
    p.add_argument("--crl", default=None, help="CRL file or URL")
    p.add_argument("--ocsp", action="store_true", help="Enable OCSP checking")
    p.add_argument("--ocsp-url", default=None, help="Override OCSP responder URL")
    p.add_argument("--mode", choices=["chain", "full"], default="full")
    p.add_argument("--validation-time", default=None, help="Override validation time (ISO 8601)")
    p.add_argument("--format", choices=["table", "json"], default="table")
    p.add_argument("--log-file", default=None)

    p = client_sub.add_parser("check-status", help="Check revocation status (OCSP/CRL)")
    p.set_defaults(_run=cmd_client_check_status)
    p.add_argument("--cert", required=True, help="Certificate PEM")
    p.add_argument("--ca-cert", required=True, help="Issuer CA certificate PEM")
    p.add_argument("--crl", default=None, help="CRL file or URL")
    p.add_argument("--ocsp-url", default=None, help="Override OCSP responder URL")
    p.add_argument("--log-file", default=None)

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(0)

    if args.command == "ca":
        if not getattr(args, "ca_command", None):
            ca_parser.print_help()
            sys.exit(0)
        if getattr(args, "db_path", None) is None and getattr(args, "out_dir", None):
            args.db_path = _default_db_path_for_out_dir(args.out_dir)
        run = getattr(args, "_run", None)
        if run:
            sys.exit(run(args))
    elif args.command == "db":
        if not getattr(args, "db_command", None):
            db_parser.print_help()
            sys.exit(0)
        run = getattr(args, "_run", None)
        if run:
            sys.exit(run(args))
    elif args.command == "repo":
        if not getattr(args, "repo_command", None):
            repo_parser.print_help()
            sys.exit(0)
        run = getattr(args, "_run", None)
        if run:
            sys.exit(run(args))
    elif args.command == "ocsp":
        if not getattr(args, "ocsp_command", None):
            ocsp_parser.print_help()
            sys.exit(0)
        run = getattr(args, "_run", None)
        if run:
            sys.exit(run(args))
    elif args.command == "client":
        if not getattr(args, "client_command", None):
            client_parser.print_help()
            sys.exit(0)
        run = getattr(args, "_run", None)
        if run:
            sys.exit(run(args))
    elif args.command == "audit":
        if not getattr(args, "audit_command", None):
            audit_parser.print_help()
            sys.exit(0)
        run = getattr(args, "_run", None)
        if run:
            sys.exit(run(args))
    elif args.command == "demo":
        if not getattr(args, "demo_command", None):
            demo_parser.print_help()
            sys.exit(0)
        run = getattr(args, "_run", None)
        if run:
            sys.exit(run(args))

    sys.exit(0)


if __name__ == "__main__":
    main()