import base64
import socket
import os
import json
import rsa
from better_profanity import profanity


def send_data(sock, json_data):
    # Attempts to send the data to the recipient
    global client
    sock.sendto(json_data.encode(), client)
    # After every message is sent there should be an ACK packet sent back to confirm its arrival,
    # Else it will attempt to resend the data one more time before moving on to the next address
    try:
        data, server = sock.recvfrom(4096)
        jobject = json.loads(data)
        jpacket = jobject.get("type")
        # if an acknowledgement message is received then we know the data reached the recipient correctly
        if (jpacket == "ack"):
            print("ACK packet received")
        else:
            print("No ACK packet received")
            raise socket.error
    except socket.timeout:
        print("socket timed out")


def receive_data(sock, expected_message_type):
    # Attempts to receive data from recipient
    data, address = sock.recvfrom(4096)

    # sets client address
    global client
    client = address

    jobject = json.loads(data)
    jpacket = jobject.get("type")

    if jpacket != expected_message_type:
        raise Exception()

    if jpacket == "sync":
        print("Connection initialized with: ", client)

    elif jpacket == "sender_public_key":
        global senderKey
        senderKey = rsa.PublicKey.load_pkcs1(jobject.get("content").encode())

    elif jpacket == "message":
        pmessage = jobject.get("content")
        decode_message = base64.b64decode(pmessage)
        pmessage = rsa.decrypt(decode_message, privateKey).decode()
        print(profanity.censor(pmessage))

        # cache = dict()
        # def get_pmessage_from_server(pmessage):
        #     response = requests.get(pmessage)
        #     return response.text
        #
        # def get_pmessage(pmessage):
        #     if pmessage not in cache:
        #         cache[pmessage] = get_pmessage_from_server(pmessage)
        #
        #     return cache[pmessage]
        #
        # print("Previous messages: \n" + get_pmessage(pmessage))

    elif jpacket == "fin":
        print("Terminating connection")

    # sends an ACK packet back to confirm the data was received
    data = {"type": "ack"}
    json_data = json.dumps(data)
    sock.sendto(json_data.encode(), address)

local_user = os.getlogin()

global senderKey

""" 
Generates a new RSA private and public key
"""
publicKey, privateKey = rsa.newkeys(2048)

server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

server_socket.bind(('127.0.0.1', 12001))

server_socket.settimeout(2)


# Client that's sending messages to it currently
global client

print("Started receiver server")

while True:
    # client set to null
    client = ()

    """
    A connection is established, the client is set
    """
    try:
        receive_data(server_socket, "sync")
    except:
        continue

    """ 
    Encryption public key is received
    """
    try:
        receive_data(server_socket, "sender_public_key")
    except:
        continue

    """
    Sending our own encryption public key
    """
    # Converts public key to PEM format as bytes
    publicKey_packet = publicKey.save_pkcs1().decode()
    message = {"type": "recipient_public_key", "content": publicKey_packet}
    data = json.dumps(message)
    try:
        send_data(server_socket, data)
    except:
        continue

    """
    Our username is requested
    """
    try:
        receive_data(server_socket, "request_username")
    except socket.timeout as inst:
        print("Exception occurred at 4")
        continue

    """
    Sending our username
    """
    # This RSA algorithm encrypts with latin-1 encoding
    encrypt_username = rsa.encrypt(local_user.encode(), senderKey)
    encrypt_username = base64.b16encode(encrypt_username)
    str(encrypt_username, "latin-1")

    data = {"type": "recipient_username", "content": encrypt_username}
    data = json.dumps(data)
    try:
        send_data(server_socket, data)
    except:
        continue

    """
    A message is received
    """
    try:
        receive_data(server_socket, "message")
    except:
        continue

    """
    Reply with our own message
    """
    message = "\n\nThank you for your message!\n\n"
    message = rsa.encrypt(message.encode(), senderKey)
    message = base64.b64encode(message)
    message = str(message, "latin-1")

    data = {"type": "message", "content": message}
    data = json.dumps(data)
    try:
        send_data(server_socket, data)
    except:
        continue

    """
    Ending communication with client
    """
    try:
        receive_data(server_socket, "fin")
        server_socket.close()
    except:
        print("closed")