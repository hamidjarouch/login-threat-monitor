"""Local dashboard. Python standard library only; no pip installation needed."""
import json
import secrets
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from detector import analyze

ROOT = Path(__file__).resolve().parent
TOKEN = secrets.token_urlsafe(32)

class Handler(BaseHTTPRequestHandler):
    def reply(self, status, data, kind='application/json; charset=utf-8'):
        if not isinstance(data, bytes):
            data = json.dumps(data, ensure_ascii=False).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', kind)
        self.send_header('Content-Length', str(len(data)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'DENY')
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        paths = {'/': ('web/index.html','text/html; charset=utf-8'),
                 '/app.js':('web/app.js','text/javascript; charset=utf-8'),
                 '/style.css':('web/style.css','text/css; charset=utf-8'),
                 '/sample.csv':('sample.csv','text/csv; charset=utf-8')}
        if self.path not in paths:
            return self.reply(404, {'error':'Not found'})
        path, kind = paths[self.path]
        content = (ROOT / path).read_bytes()
        if self.path == '/':
            content = content.replace(b'__TOKEN__', TOKEN.encode())
        self.reply(200, content, kind)

    def do_POST(self):
        if self.path != '/analyze':
            return self.reply(404, {'error':'Not found'})
        if self.headers.get('X-App-Token') != TOKEN:
            return self.reply(403, {'error':'Reload the dashboard and retry.'})
        try:
            length = int(self.headers.get('Content-Length', '0'))
            if not 0 < length <= 4_000_000:
                raise ValueError('Request must be smaller than 4 MB.')
            data = json.loads(self.rfile.read(length))
            if not isinstance(data, dict) or not isinstance(data.get('csv'), str):
                raise ValueError('Expected CSV text.')
            result = analyze(data['csv'], data.get('threshold',3), data.get('minutes',5))
            self.reply(200, result)
        except (ValueError, UnicodeError, TypeError) as exc:
            self.reply(400, {'error':str(exc)})

    def log_message(self, *_):
        pass

if __name__ == '__main__':
    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    server.daemon_threads = True
    url = f'http://127.0.0.1:{server.server_port}'
    print(f'Login Threat Monitor\nOpen: {url}\nKeep this window open. Ctrl+C stops the app.')
    threading.Timer(0.5, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
