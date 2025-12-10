#!/bin/bash
echo "Starting HTTPS server on port 8443..."
echo "Visit: https://localhost:8443/test.html"
echo "Press Ctrl+C to stop"
python3 -c "
import http.server, ssl

httpd = http.server.HTTPServer(('0.0.0.0', 8443), http.server.SimpleHTTPRequestHandler)

# Modern SSL context (Python 3.12+)
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain('myapp.dev+4.pem', 'myapp.dev+4-key.pem')
httpd.socket = context.wrap_socket(httpd.socket, server_side=True)

print('Server running at https://localhost:8443')
httpd.serve_forever()
"
