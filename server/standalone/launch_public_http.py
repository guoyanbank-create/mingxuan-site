"""Explicit opt-in public HTTP launcher. Never invoke user input through a shell."""
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parent


def main(argv=None):
    args = list(sys.argv[1:] if argv is None else argv)
    if args not in ([], ['--check-runtime'], ['--configure']):
        print('Usage: launch_public_http.py [--check-runtime | --configure]')
        return 1
    from check_python_legacy import main as check_runtime
    if check_runtime(['--quiet']) != 0:
        print('[ERROR] Python 3.8+ and the required standard-library capabilities are needed.')
        return 1
    if args == ['--check-runtime']:
        return 0
    from server import Invalid, validate_http_public_origin
    import sqlite3
    print('Python: ' + sys.version.split()[0] + ' | SQLite: ' + sqlite3.sqlite_version)
    try:
        import ssl
        print('TLS library: ' + ssl.OPENSSL_VERSION + ' (not used by this HTTP listener)')
    except ImportError:
        print('TLS library: unavailable (not required for HTTP; optional HTTPS AI unavailable)')
    print('警告：这是明确开启的公网 HTTP 明文模式。')
    print('家庭密码、登录会话和学习记录可能被窃听、篡改；请勿复用其他网站密码。')
    print('Windows Server 2008 R2 / Python 3.8 已停止安全维护；此启动器不是安全升级。')
    print('本程序不会修改防火墙、端口映射、IIS、系统服务或其他应用。')
    config = ROOT/'data'/'public-http.json'
    try:
        if config.exists() and args != ['--configure']:
            saved = json.loads(config.read_text(encoding='utf-8'))
            if not isinstance(saved, dict) or set(saved) != {'origin'}:
                raise Invalid('公网地址配置格式无效')
            origin = validate_http_public_origin(saved['origin'])
        else:
            origin = validate_http_public_origin(input('请输入完整公网地址，例如 http://1.2.3.4:11111（不要加路径，不用提供密码）：').strip())
            config.parent.mkdir(parents=True, exist_ok=True)
            # This file contains only a public origin, never a password or API key.
            temp = config.with_suffix('.json.tmp')
            with temp.open('w', encoding='utf-8') as f:
                json.dump({'origin':origin}, f, ensure_ascii=False)
            os.replace(str(temp), str(config))
        auth = ROOT/'data'/'auth.json'
        if not auth.exists():
            code = subprocess.call([sys.executable, str(ROOT/'server.py'), 'setup-auth'], shell=False)
            if code:
                return code
        print('浏览器访问：' + origin + '/')
        print('关闭本窗口将停止学习站。若需要更改地址，可单独删除 data/public-http.json 后重启。')
        command = [sys.executable, str(ROOT/'server.py'), '--host', '0.0.0.0', '--port', '11111',
                   '--allow-insecure-public-http', '--public-origin', origin]
        return subprocess.call(command, shell=False)
    except (Invalid, OSError, ValueError, EOFError) as exc:
        # Only local setup errors; do not print raw data/configuration values.
        print('启动未完成：' + (str(exc) if isinstance(exc, Invalid) else type(exc).__name__))
        print('请核对公网地址格式、文件权限和必需文件；不要删除 data/auth.json 或 study.db。')
        return 1
    except KeyboardInterrupt:
        return 0

if __name__ == '__main__':
    sys.exit(main())
