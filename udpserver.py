import base64
import socket
import os
import json
import rsa
from better_profanity import profanity
import zlib


def calculate_checksum(data):
    name = data.get("type")
    content = data.get("content")
    if name is None:
        name = ""
    if content is None:
        content = ""
    checksum_sequence = name + content

    checksum = zlib.crc32(bytes(checksum_sequence, "utf-8"))
    return checksum

def send_data(sock, json_data):
    # calculates checksum and puts it in json object
    checksum_value = calculate_checksum(json_data)
    # append checksum to json
    json_data['checksum'] = checksum_value

    json_data = json.dumps(json_data)

    # Attempts to send the data to the recipient
    global client
    # print("Trying to send data...", json_data)
    print("Trying to send data...")
    sock.sendto(json_data.encode(), client)
    # After every message is sent there should be an ACK packet sent back to confirm its arrival,
    # Else it will attempt to resend the data one more time before moving on to the next address
    print("Waiting to receive...")
    data, server = sock.recvfrom(4096)
    # print("Received ", data)
    jobject = json.loads(data)
    jpacket = jobject.get("type")

    if jobject.get("checksum") is not None:
        if calculate_checksum(jobject) != int(jobject.get("checksum")):
            print("Checksums don't match. Need to resend the packet")
            raise Exception()
        else:
            print("Checksum on ACK matches")

    # if an acknowledgement message is received then we know the data reached the recipient correctly
    if jpacket == "ack":
        print("ACK packet received")
    else:
        print("No ACK packet received")
        raise socket.error


def receive_data(sock, expected_message_type):
    # Attempts to receive data from recipient
    data, address = sock.recvfrom(4096)
    # print("Server expected_message_type", expected_message_type)
    # print("Server received data", data)
    print("Server received data")
    global client
    client = address

    jobject = json.loads(data)
    # print("JSON data ", jobject)

    if jobject.get("checksum") is not None:
        if calculate_checksum(jobject) != int(jobject.get("checksum")):
            print("Checksums don't match. Need to resend the packet")
            raise Exception()
        else:
            print("Checksums match")

    jpacket = jobject.get("type")
    # print("Server packet ", jpacket)
    # if jpacket != expected_message_type:
    #     print("packet is not what is expected message type. Packet ", jpacket, " expected message ", expected_message_type)
    #     raise Exception()

    if jpacket == "sync":
        print("Connection initialized with: ", client)

    elif jpacket == "sender_public_key":
        print("Got public key")
        global sender_key
        # print("Public key is ", jobject.get("content"))
        sender_key = rsa.PublicKey.load_pkcs1(jobject.get("content"))

    elif jpacket == "message":

        message = jobject.get("content")
        decode_message = base64.b64decode(message)
        message = rsa.decrypt(decode_message, privateKey).decode()

        filtered_message = profanity.censor(message)
        message_cache.append(filtered_message)
        print("\n\nHere's the message received:\n-+-+-+-+-\n"+filtered_message+"\n-+-+-+-+-\n\n")


    elif jpacket == "fin":
        print("Terminating connection")

    print("Encoding message to send back")
    # sends an ACK packet back to confirm the data was received
    data = {"type": "ack"}

    # Calculates checksum. Includes it in jobject
    checksum_value = calculate_checksum(data)

    # adding checksum to json
    data['checksum'] = checksum_value

    json_data = json.dumps(data)
    # print("Trying to return data to client ", json_data)
    print("Trying to return data to client ")
    sock.sendto(json_data.encode(), address)


local_user = "Seoeun"

reply_message = str(input("Please enter a response (optional): "))
# Default response when user decides to not respond
if reply_message == "":
    reply_message = "\n\nThanks for the message.\n\n"

global sender_key

""" 
Generates a new RSA private and public key
"""
publicKey, privateKey = rsa.newkeys(2048)

server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

server_socket.bind(('127.0.0.1', 12000))



# Client sending live messages to it
global client

# cache storing messages
global message_cache
message_cache = []

print("Started receiver server")

while True:
    # client set to null
    client = ()
    print("Server listening for next message")

    """
    A connection is established, the client is set
    """
    try:
        receive_data(server_socket, "sync")
    except KeyboardInterrupt:
        break
    # except:
    #     continue

    """ 
    Encryption public key is received
    """
    try:
        receive_data(server_socket, "sender_public_key")
    except KeyboardInterrupt:
        break
    # except:
    #     continue

    """
    Sending our own encryption public key
    """
    # Converts public key to PEM format as bytes
    publicKey_packet = publicKey.save_pkcs1().decode()
    data = {"type": "recipient_public_key", "content": publicKey_packet}

    try:
        send_data(server_socket, data)
        print("Sent public key")
    except KeyboardInterrupt:
        break
    # except:
    #     continue

    """
    The username is requested
    """
    try:
        receive_data(server_socket, "request_username")
    except KeyboardInterrupt:
        break
    # except:
    #     continue

    """
    Sending our username
    """
    # This RSA algorithm encrypts with latin-1 encoding
    encrypt_username = rsa.encrypt(local_user.encode(), sender_key)
    encrypt_username = base64.b64encode(encrypt_username)
    encrypt_username = str(encrypt_username, "latin-1")

    data = {"type": "recipient_username", "content": encrypt_username}

    try:
        send_data(server_socket, data)
    except KeyboardInterrupt:
        break
    except:
        continue

    """
    A message is received
    """
    try:
        receive_data(server_socket, "message")
    except KeyboardInterrupt:
        break
    except:
        continue

    """
    Reply with own message
    """

    message = rsa.encrypt(reply_message.encode(), sender_key)
    message = base64.b64encode(message)
    message = str(message, "latin-1")

    data = {"type": "message", "content": message}
    try:
        send_data(server_socket, data)
    except KeyboardInterrupt:
        break
    except:
        continue

    """
    Ending communication with client
    """
    try:
        receive_data(server_socket, "fin")
    except KeyboardInterrupt:
        break
    except:
        print("closed")
        continue

    break
# close socket.
server_socket.close()

print("\n\nCached messages:\n")

for i, cache in enumerate(message_cache):
    print(cache)

print("\nEnd of program")
