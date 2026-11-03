"""Legacy-only diagnostic probe. No persistent files, secrets or network calls."""
import sys

def main(argv=None):
    import argparse
    parser = argparse.ArgumentParser(description='Legacy runtime diagnostics; no network or persistent data.')
    parser.add_argument('--quiet', action='store_true')
    parser.add_argument('--bind-host', default='127.0.0.1')
    args = parser.parse_args(argv)
    quiet = args.quiet
    if args.bind_host != '127.0.0.1':
        if not quiet:
            print('[ERROR] Legacy IIS mode allows only exact 127.0.0.1 binding.')
        return 1
    if sys.version_info < (3, 8):
        if not quiet:
            print('[ERROR] This legacy launcher requires Python 3.8 or newer.')
        return 1
    stage = "required standard modules"
    def require(condition):
        if not condition:
            raise RuntimeError("capability check failed")
    try:
        import argparse
        import getpass
        import hashlib
        import hmac
        import http.client
        import http.cookies
        import http.server
        import ipaddress
        import json
        import pathlib
        import secrets
        import sqlite3
        import threading
        import urllib.request
        from datetime import timezone
        stage = 'threaded HTTP server'
        require(hasattr(http.server, 'ThreadingHTTPServer'))
        stage = 'secure random source'
        require(len(secrets.token_bytes(16)) == 16)
        stage = 'PBKDF2 and constant-time comparison'
        digest = hashlib.pbkdf2_hmac('sha256', b'diagnostic-only', b'not-a-credential', 1)
        require(len(digest) == 32 and hmac.compare_digest(digest, digest))
        stage = 'exact loopback address'
        require(ipaddress.ip_address('127.0.0.1').is_loopback)
        stage = 'in-memory SQLite transaction'
        db = sqlite3.connect(':memory:')
        try:
            db.execute('CREATE TABLE diagnostic (id INTEGER PRIMARY KEY, value TEXT)')
            db.execute('BEGIN IMMEDIATE')
            db.execute('INSERT INTO diagnostic VALUES (?,?)', (1, 'temporary'))
            db.commit()
            require(db.execute('SELECT value FROM diagnostic WHERE id=1').fetchone()[0] == 'temporary')
        finally:
            db.close()
    except Exception as exc:
        if not quiet:
            print('[ERROR] ' + stage + ' failed: ' + type(exc).__name__)
        return 1
    tls = 'not available; optional AI HTTPS cannot run'
    tls_flags = 'unavailable'
    try:
        import ssl
        tls = ssl.OPENSSL_VERSION
        ctx = ssl.create_default_context()
        tls_flags = 'TLS1.2=%s; SNI=%s; certificate verification=%s' % (getattr(ssl, 'HAS_TLSv1_2', False), ssl.HAS_SNI, ctx.check_hostname and ctx.verify_mode == ssl.CERT_REQUIRED)
    except Exception:
        pass
    if not quiet:
        print('Bind host: ' + args.bind_host)
        print('Python: ' + sys.version.split()[0])
        print('SQLite: ' + sqlite3.sqlite_version)
        print('TLS library: ' + tls)
        print('TLS diagnostics only: ' + tls_flags)
        print('Required modules / PBKDF2 / in-memory SQLite transaction: passed')
        print('WARNING: Legacy Windows and Python 3.8 are end-of-life.')
        print('This check does NOT prove IIS connectivity or restore security updates.')
        print('No software installed; no persistent credentials/data created; no network calls.')
    return 0

if __name__ == '__main__':
    sys.exit(main())
