"""Command-line interface for MicroPKI."""

import argparse
import sys
from pathlib import Path
import os

from . import logger
from . import crypto_utils
from . import certificates
from . import ca


def create_parser() -> argparse.ArgumentParser:
    """Create the argument parser for the CLI."""
    parser = argparse.ArgumentParser(
        description="MicroPKI - Lightweight Public Key Infrastructure tool",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    # Global arguments
    parser.add_argument(
        '--log-file',
        help='Path to log file (if omitted, logs go to stderr)'
    )

    # Subcommands
    subparsers = parser.add_subparsers(
        title='commands',
        dest='command',
        required=True,
        help='Available commands'
    )

    # ca init subcommand
    ca_parser = subparsers.add_parser('ca', help='CA operations')
    ca_subparsers = ca_parser.add_subparsers(
        dest='ca_command',
        required=True,
        help='CA subcommands'
    )

    init_parser = ca_subparsers.add_parser('init', help='Initialize a new Root CA')

    # Arguments for ca init
    init_parser.add_argument(
        '--subject',
        required=True,
        help='Distinguished Name (e.g., "/CN=My Root CA" or "CN=My Root CA,O=Demo,C=US")'
    )

    init_parser.add_argument(
        '--key-type',
        choices=['rsa', 'ecc'],
        default='rsa',
        help='Key type (default: rsa)'
    )

    init_parser.add_argument(
        '--key-size',
        type=int,
        default=4096,
        help='Key size in bits (4096 for RSA, 384 for ECC, default: 4096)'
    )

    init_parser.add_argument(
        '--passphrase-file',
        required=True,
        help='Path to file containing the passphrase for private key encryption'
    )

    init_parser.add_argument(
        '--out-dir',
        default='./pki',
        help='Output directory (default: ./pki)'
    )

    init_parser.add_argument(
        '--validity-days',
        type=int,
        default=3650,
        help='Validity period in days (default: 3650 ≈ 10 years)'
    )

    # Optional force flag for overwriting
    init_parser.add_argument(
        '--force',
        action='store_true',
        help='Force overwrite of existing files'
    )

    return parser


def validate_args(args: argparse.Namespace, log) -> bool:
    """
    Validate command-line arguments.

    Returns:
        True if validation passes, False otherwise.
    """
    # Validate key-type and key-size combination
    if args.key_type == 'rsa' and args.key_size != 4096:
        log.error(f"RSA key size must be 4096, got {args.key_size}")
        return False

    if args.key_type == 'ecc' and args.key_size != 384:
        log.error(f"ECC key size must be 384, got {args.key_size}")
        return False

    # Validate passphrase file
    passphrase_file = Path(args.passphrase_file)
    if not passphrase_file.exists():
        log.error(f"Passphrase file not found: {args.passphrase_file}")
        return False

    if not os.access(passphrase_file, os.R_OK):
        log.error(f"Cannot read passphrase file: {args.passphrase_file}")
        return False

    # Validate output directory
    out_dir = Path(args.out_dir)
    if out_dir.exists():
        if not os.access(out_dir, os.W_OK):
            log.error(f"Output directory is not writable: {out_dir}")
            return False

        # Check for existing files if not force
        if not args.force:
            key_file = out_dir / "private" / "ca.key.pem"
            cert_file = out_dir / "certs" / "ca.cert.pem"

            if key_file.exists() or cert_file.exists():
                log.error(
                    "Output directory already contains CA files. "
                    "Use --force to overwrite or choose a different --out-dir"
                )
                return False
    else:
        # Try to create the directory
        try:
            out_dir.mkdir(parents=True, exist_ok=True)
        except PermissionError:
            log.error(f"Cannot create output directory: {out_dir}")
            return False

    # Validate validity days
    if args.validity_days <= 0:
        log.error(f"Validity days must be positive, got {args.validity_days}")
        return False

    return True


def main():
    """Main entry point for the CLI."""
    parser = create_parser()
    args = parser.parse_args()

    # Setup logging
    log = logger.setup_logger(args.log_file)

    try:
        # Handle commands
        if args.command == 'ca' and args.ca_command == 'init':
            log.info("Starting Root CA initialization")

            # Validate arguments
            if not validate_args(args, log):
                sys.exit(1)

            # Read passphrase
            try:
                passphrase = crypto_utils.read_passphrase_from_file(args.passphrase_file)
                log.info("Successfully read passphrase file")
            except (FileNotFoundError, PermissionError) as e:
                log.error(f"Failed to read passphrase file: {e}")
                sys.exit(1)

            # Generate key pair
            log.info(f"Generating {args.key_type.upper()} key pair...")
            try:
                if args.key_type == 'rsa':
                    private_key = crypto_utils.generate_rsa_key(args.key_size)
                else:  # ecc
                    private_key = crypto_utils.generate_ecc_key()
                log.info("Key generation completed successfully")
            except Exception as e:
                log.error(f"Key generation failed: {e}")
                sys.exit(1)

            # Encrypt private key
            log.info("Encrypting private key...")
            try:
                encrypted_key = crypto_utils.encrypt_private_key(private_key, passphrase)
                log.info("Key encryption completed")
            except Exception as e:
                log.error(f"Key encryption failed: {e}")
                sys.exit(1)

            # Save encrypted key
            out_dir = Path(args.out_dir)
            key_path = crypto_utils.save_encrypted_key(encrypted_key, out_dir, log)

            # Generate self-signed certificate
            log.info("Generating self-signed certificate...")
            try:
                certificate = certificates.create_self_signed_certificate(
                    args.subject,
                    private_key,
                    args.validity_days,
                    log
                )
                log.info("Certificate generation completed")
            except Exception as e:
                log.error(f"Certificate generation failed: {e}")
                sys.exit(1)

            # Save certificate
            cert_path = certificates.save_certificate(certificate, out_dir, log)

            # Generate policy file
            log.info("Generating policy document...")
            try:
                policy_path = ca.generate_policy_file(
                    out_dir,
                    args.subject,
                    certificate,
                    args.key_type,
                    args.key_size,
                    log
                )
                log.info(f"Policy document saved to {policy_path}")
            except Exception as e:
                log.error(f"Policy generation failed: {e}")
                sys.exit(1)

            log.info("Root CA initialization completed successfully")
            print(f"\n✅ Root CA successfully initialized in: {out_dir.absolute()}")
            print(f"   Certificate: {cert_path}")
            print(f"   Private key: {key_path}")
            print(f"   Policy: {policy_path}")

        else:
            parser.print_help()

    except KeyboardInterrupt:
        log.warning("Operation interrupted by user")
        sys.exit(1)
    except Exception as e:
        log.error(f"Unexpected error: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()