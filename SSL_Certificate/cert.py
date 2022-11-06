import sys
import ssl
import urllib.parse

url = sys.argv[1]
url = "http://thesishua.herokuapp.com/"
addr = urllib.parse.urlsplit(url).hostname
port = 443
try:
        cert = ssl.get_server_certificate((addr, port), ssl_version=2)
        print(cert)
except ssl.SSLError as e:
        print("Handshake Failed")