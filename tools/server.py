from tools.message import Message
from tools.token import Token, InvalidToken
from tools.oracle import Oracle
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse

class AuthenticatorApp():
    def __init__(self):
        self.oracle = Oracle()

    def checkQuery(self, query):
        query_msg = Message(query, 'ascii')
        try:
            token = Token.fromMsg(query_msg, sep_field=Message(b'&'), sep_key=Message(b'='))
            filename = token.data[Message(b'file')].ascii()
            with open(filename, 'r') as infile:
                file_contents = Message(infile.read(), 'ascii')
            mac = token.data[Message(b'signature')].ascii()
            return self.oracle.checkHMACSHA1(file_contents, mac)
        except (IndexError, KeyError):
            raise InvalidToken

class RequestHandler(BaseHTTPRequestHandler):
    def __init__(self, request, client_address, server, authenticator):
        # add our extra attribute to self before calling the parent constructor...
        self.authenticator = authenticator
        # ...because the parent constructor also handles the request, cleans up, and closes the connection!
        BaseHTTPRequestHandler.__init__(self, request, client_address, server)

    def do_GET(self):
         result = urlparse(self.path)
         query = result.query
         try:
             if self.authenticator.checkQuery(query):
                 self.send_response(200)
             else:
                 self.send_response(500)
         except InvalidToken:
             self.send_response(404)
         return

class Server(HTTPServer):
    def __init__(self, server_address):
        HTTPServer.__init__(self, server_address, RequestHandler)
        self.authenticator = AuthenticatorApp()

    def run(self):
        self.serve_forever()
 

