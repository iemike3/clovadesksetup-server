from socketserver import ThreadingTCPServer
from http.server import SimpleHTTPRequestHandler
import ssl
import warnings
import os
import sys
import subprocess
import json
from datetime import datetime, timedelta
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509

class ClovaServer(ThreadingTCPServer):
    allow_reuse_address = True

class ClovaRequestHandler(SimpleHTTPRequestHandler):
    def do_GET(self):
        print(self.headers)
        print(self.path)
        if self.path.startswith("/token?"):
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            re_js = {
                "token_type": "clovatoken",
                "access_token": "1",
                "refresh_token": "",
                "expires_in": "0"
            }
            self.wfile.write(json.dumps(re_js).encode('utf-8'))

def generate_certificate(cert_path, key_path):
    # Generate private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    # Write private key to file
    with open(key_path, 'wb') as key_file:
        key_file.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    # Generate certificate
    subject = issuer = x509.Name([
        x509.NameAttribute(x509.NameOID.COMMON_NAME, u'ClovaHack')
    ])

    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.utcnow()
    ).not_valid_after(
        datetime.utcnow() + timedelta(days=3650)
    ).add_extension(
        x509.SubjectAlternativeName([
            x509.DNSName(u'clova-authgw.line-apps.com'),
            x509.DNSName(u'clova-ota-auth.line-apps.com'),
            x509.DNSName(u'clova-cic.line-apps.com'),
        ]),
        critical=False
    ).sign(
        private_key,
        algorithm=hashes.SHA256(),
        backend=default_backend()
    )

    # Write certificate to file
    with open(cert_path, 'wb') as cert_file:
        cert_file.write(cert.public_bytes(serialization.Encoding.PEM))

def check_hosts_file():
    hosts_file_path = r'C:\\Windows\\System32\\drivers\\etc\\hosts'
    target_host_entry = '192.168.137.1 clova-authgw.line-apps.com'

    try:
        with open(hosts_file_path, 'r') as hosts_file:
            content = hosts_file.read().splitlines()
            matching_lines = [line for line in content if line.strip() == target_host_entry]
            if not matching_lines:
                print("\033[31m" + "\r\nERROR!\r\n\r\n" + "\033[0m" + f"{hosts_file_path} に '{target_host_entry}' が設定されていません｡\r\nクリップボードから空白行に貼り付けてください｡" + "\r\n")
                subprocess.Popen(f'notepad {hosts_file_path}')
                subprocess.run("clip", input=target_host_entry, text=True)
                sys.exit()
    except FileNotFoundError:
        print("\033[31m" + "\r\nERROR!\r\n\r\n" + "\033[0m" + f"Error: {hosts_file_path} が見つかりませんでした｡")
        sys.exit()


def run_server():
    check_hosts_file()

    host = "0.0.0.0"
    port = 443
    cert_path = 'server.crt'
    key_path = 'server.key'

    # server.crt と server.key のどちらかが存在しない場合、もしくは両方が存在しない場合に削除
    if not (os.path.exists(cert_path) and os.path.exists(key_path)):
        try:
            os.remove(cert_path)
            os.remove(key_path)
        except FileNotFoundError:
            pass

        # 新しい証明書を生成
        print("\r\n証明書を作成中です...")
        generate_certificate(cert_path, key_path)
        print("\r\n証明書を作成しました")

    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ctx.load_cert_chain(cert_path, keyfile=key_path)
    ctx.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1

    httpd = ClovaServer((host, port), ClovaRequestHandler)
    httpd.socket = ctx.wrap_socket(httpd.socket)
    
    print('\r\n[*] Proxy Listening at', f'{host}:{port}',"\r\n")

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        sys.exit()

if __name__ == "__main__":
    warnings.filterwarnings("ignore", category=DeprecationWarning)
    run_server()
