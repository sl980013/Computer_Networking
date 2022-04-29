import socket
import os
import json
import rsa


def send_data(sock, jsonData):
    # Attempts to send the data to the recipient
    global client
    sock.sendto(jsonData.encode(), client)
    # After every message is sent there should be an ACK packet sent back to confirm it's arrival,
    # Else it will attempt to resend the data one more time before moving on to the next address
    try:
        data, server = sock.recvfrom(4096)
        jsonObj = json.loads(data)
        jpacket = jsonObj.get("type")
        # if an acknowledgement message is received then we know the data reached the recipient correctly
        if (jpacket == "ack"):
            print("ACK packet received")
        else:
            print("No ACK packet received")
            raise socket.error
    except socket.timeout:
        print("socket timed out")


def receive_data(sock, expectedMessageType):
    # Attempts to receive data from recipient
    data, address = sock.recvfrom(4096)

    # sets client address
    global client
    client = address

    jsonObj = json.loads(data)
    jpacket = jsonObj.get("type")

    if jpacket != expectedMessageType:
        raise Exception()

    if jpacket == "sync":
        print("Connection initialized with: ",client)

    elif jpacket == "sender_public_key":
        global senderKey
        senderKey = rsa.PublicKey.load_pkcs1(jsonObj.get("content").encode())

    elif jpacket == "message":
        print(rsa.decrypt(jsonObj.get("content").encode('latin-1'), privateKey).decode() )

    elif jpacket == "fin":
        print("Terminating connection")

    # sends an ACK packet back to confirm the data was received
    data = {"type": "ack"}
    jsonData = json.dumps(data)
    sock.sendto(jsonData.encode(), address)

local_user = os.getlogin()

global senderKey

## Generates a new RSA private and public key
publicKey, privateKey = rsa.newkeys(2048)

serverSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

serverSocket.bind(('127.0.0.1', 12001))

serverSocket.settimeout(2)


# Client that's sending messages to it currently
global client



print("Started receiver server")

while True:
    # client set to null
    client = ()
##### A connection is established, the client is set

    try:
        receive_data(serverSocket, "sync")
    except:
        continue

#### Encryption public key is received
    try:
        receive_data(serverSocket, "sender_public_key")
    except:
        continue

### Sending our own encryption public key
    # Converts public key to PEM format as bytes
    publicKey_packet = publicKey.save_pkcs1().decode()
    message = {"type": "recipient_public_key", "content": publicKey_packet }
    data = json.dumps(message)
    try:
        send_data(serverSocket, data)
    except:
        continue

#### Our username is requested
    try:
        receive_data(serverSocket, "request_username")
    except socket.timeout as inst:
        print("Exception occurred at 4")
        continue

#### Sending our username

    # This RSA algorithm encrypts with latin-1 encoding
    encryptedUsername = rsa.encrypt(local_user.encode(), senderKey).decode('latin-1')

    data = {"type": "recipient_username", "content": encryptedUsername}
    data = json.dumps(data)
    try:
        send_data(serverSocket, data)
    except:
        continue

#### A message is received
    try:
        receive_data(serverSocket, "message")
    except:
        continue

#### Replying with our own message
    message = "\n\nThank you for your message!\n\n"
    message = rsa.encrypt(message.encode(), senderKey).decode('latin-1')
    data = {"type": "message", "content": message}
    data = json.dumps(data)
    try:
        send_data(serverSocket, data)
    except:
        continue

#### Ending communication with client
    try:
        receive_data(serverSocket, "fin")
    except:
        print("closed")