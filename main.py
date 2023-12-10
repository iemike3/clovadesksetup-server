
from socketserver import ThreadingTCPServer, BaseRequestHandler
from http.server import HTTPServer, SimpleHTTPRequestHandler
import ssl

ThreadingTCPServer.allow_reuse_address = True

class class1(SimpleHTTPRequestHandler):
    
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
        return

host = "0.0.0.0"
port = 443
ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
ctx.load_cert_chain('server.crt', keyfile='server.key')
ctx.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1
httpd = ThreadingTCPServer((host, port), class1)
httpd.socket = ctx.wrap_socket(httpd.socket)
print('[*] Proxy Listening at', host + ":" +  str(port))
httpd.serve_forever()
