from tools.server import Server
from tools.message import Message
from tools.authentication import hmacSHA1

server_address = ('127.0.0.1', 8080)
server = Server(server_address)
key = server.authenticator.oracle.key
print("The server's key is:", key)
msg = Message(b'some text, more text, and yet more text\n')
hmac = hmacSHA1(key, msg)
print("The correct signature is:", hmac)

server.run()
