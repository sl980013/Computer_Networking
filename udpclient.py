import socket
import os
import json
import rsa
import datetime
import zlib
from better_profanity import profanity

""""
Use CRC32 to calculate a checksum for our data to be sent
Take json data to compare the checksum with the calculated checksum in json object
checksum is applied on the type and message content of the json
"""""

def calculate_checksum(data):
    name = data.get("type")
    message_content = data.get("content")
    if name is None:
        name = ""
    if message_content is None:
        message_content = ""
    checksum_seq = name + message_content

    checksum = zlib.crc32(bytes(checksum_seq, "utf-8"))
    return checksum


def send_data(sock, json_data):

    # checksum calculation- puts it in json object
    checksum_value = calculate_checksum(json_data)
    # append checksum to json
    json_data['checksum'] = checksum_value

    json_data = json.dumps(json_data)

    # Attempts to send the data to the recipient
    sock.sendto(json_data.encode(), UDP_ADDRESS)

    try:
        """
        After every message is sent there should be an ACK packet sent back to confirm it's arrival,
        Else it will attempt to resend the data one more time before moving on to the next address
        """

        data, server = sock.recvfrom(4096)
        jobject = json.loads(data)
        jpacket = jobject.get("type")
    # if an acknowledgement message is received, we know the data reached the recipient
        if jpacket == "ack":
            print("ACK packet received")
        else:
            print("No ACK packet received")
            raise socket.error

    except:
        print("No ACK packet received")
        raise socket.error


def receive_data(sock, expected_type):
    # Attempts to receive data from recipient
    data, server = sock.recvfrom(4096)

    jobject = json.loads(data)

    # Checks if the received packet has a checksum as it was optional for this implementation
    # if the checksums do not match then it will raise an exception
    if jobject.get("checksum") is not None:
        if calculate_checksum(jobject) != int(jobject.get("checksum")):
            print("Checksums do not match, need the packet resent")
            raise Exception()
        else:
            print("Checksums match")

    jpacket = jobject.get("type")

    print("Packet Type Received: ", jpacket)

    if jpacket != expected_type:
        print("Incorrect packet type received")
        raise Exception()

    if jpacket == "recipient_public_key":
        global receiver_key
        receiver_key = rsa.PublicKey.load_pkcs1(jobject.get("content").encode())
    elif jpacket == "recipient_username":
        global receiver_name
        receiver_name = rsa.decrypt(jobject.get("content").encode('latin-1'), privateKey).decode()

    elif jpacket == "message":
        print(profanity.censor(rsa.decrypt(jobject.get("content").encode('latin-1'), privateKey).decode()))
    # sends an ACK packet back to confirm the data was received
    data = {"type": "ack"}
    json_data = json.dumps(data)
    sock.sendto(json_data.encode(), UDP_ADDRESS)

local_user = os.getlogin()

# Generates a new RSA private and public key for asymmetric encryption
publicKey, privateKey = rsa.newkeys(2048)


# Define global variables
global receiver_key
global receiver_name

receiver_list = ""
while receiver_list == "":
    receiver_list = str(input("Enter the list of IP addresses you want to send greetings to with commas separating the addresses (e.g '127.0.0.1, 127.0.0.2, 127.0.0.3' ):\n"))

receiver_list = receiver_list.replace(" ", "")
receiver_list = receiver_list.split(",")
print(receiver_list)

# This message is optional. It will be taken at the start of program execution
optional_message = str(input("Please enter a message (optional): "))

# Attempts to send the greeting to each IP address that the user has entered
for i, receiver in enumerate(receiver_list):

    """
    Creating socket for current IP
    """
    # Change the IP Address to the list of IPs
    UDP_IP_ADDRESS = receiver
    try:
        socket.inet_aton(UDP_IP_ADDRESS)
        # IP is legal if it's passed
    except socket.error:
        # If it's not legal
        print("IP is not valid")
        # continue, used to end the for loop iteration for the IP entered
        continue

    # Setting the Receiver address and establishing a socket connection, setting a timeout to 1 second
    UDP_PORT_NO = 12001
    UDP_ADDRESS = (UDP_IP_ADDRESS, UDP_PORT_NO)
    socket.setdefaulttimeout(1)
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    """
    Synchronize packet for initiating connection
    """
    print("\n\nInitialising connection")
    data = {"type": "sync"}

    # Tries to send the json payload to the address
    try:
        send_data(client_socket, data)
    except socket.timeout as inst:
        # If the request times out, it attempts resending the data once. It moves on to the next address if that fails
        print("Request timed out - Resending Data")
        try:
            send_data(client_socket, data)
        except:
            print("Error, cannot establish connection with current IP, moving on to next address\n\n")
            client_socket.close()
            continue
    except socket.error:
        print("Error with connection - Resending Data")
        try:
            send_data(client_socket, data)
        except:
            print("Error, cannot establish connection with current IP, moving on to next address\n\n")
            client_socket.close()
            continue
    except:
        print("Unknown error occurred, moving on to next IP address\n\n")
        client_socket.close()
        continue

    """
    Exchange Public keys between receiver and sender
    """
    print("Exchanging public keys")
    # Converts public key to PEM format as bytes then decodes it to string
    publicKey_packet = publicKey.save_pkcs1().decode()
    data = {"type": "sender_public_key", "content": publicKey_packet }

    # Tries to send the json payload to the address
    try:
        send_data(client_socket, data)
    except socket.timeout as inst:
        # If the request times out, it attempts resending the data once. It then moves on to the next address if that fails
        print("Request timed out - Resending Data")
        try:
            send_data(client_socket, data)
        except:
            print("Error, cannot establish connection with current IP, moving on to next address\n\n")
            client_socket.close()
            continue
    except socket.error:
        print("Error with connection - Resending Data")
        try:
            send_data(client_socket, data)
        except:
            print("Error, cannot establish connection with current IP, moving on to next address\n\n")
            client_socket.close()
            continue
    except:
        print("Unknown error occurred, moving on to next IP address\n\n")
        client_socket.close()
        continue


    try:
        receive_data(client_socket, "recipient_public_key")
    except socket.timeout as inst:
        print("Socket timed out, trying again")
        try:
            receive_data(client_socket, "recipient_public_key")
        except:
            print("An Error occurred receiving data from the current IP, moving on to next address\n\n")
            client_socket.close()
            continue
    except:
        print("An error occurred, trying again")
        try:
            receive_data(client_socket, "recipient_public_key")
        except:
            print("An Error occurred receiving data from the current IP, moving on to next address\n\n")
            client_socket.close()
            continue

    """
    Sends a request for the recipient username
    """
    print("Asking for recipient username")
    data = {"type": "request_username"}
    # Tries to send the json payload to the address
    try:
        send_data(client_socket, data)
    except socket.timeout as inst:
        # If the request times out it attempts to resend the data once then will move on to the next address if that fails
        print("Request timed out - Resending Data")
        try:
            send_data(client_socket, data)
        except:
            print("Error, cannot establish connection with current IP, moving on to next address\n\n")
            client_socket.close()
            continue
    except socket.error:
        print("Error with connection - Resending Data")
        try:
            send_data(client_socket, data)
        except:
            print("Error, cannot establish connection with current IP, moving on to next address\n\n")
            client_socket.close()
            continue
    except:
        print("Unknown error occurred, moving on to next IP address\n\n")
        client_socket.close()
        continue

    """
    Receiving recipient username
    """
    try:
        receive_data(client_socket, "recipient_username")
    except socket.timeout as inst:
        print("Socket timed out, trying again")
        try:
            receive_data(client_socket, "recipient_username")
        except:
            print("An Error occurred receiving data from the current IP, moving on to next address\n\n")
            client_socket.close()
            continue
    except:
        print("An error occurred, trying again")
        try:
            receive_data(client_socket, "recipient_username")
        except:
            print("An Error occurred receiving data from the current IP, moving on to next address\n\n")
            client_socket.close()
            continue
    print(receiver_name)

    """ 
    Sending the greeting message
    """
    # Checks time to put in correct greeting of Good Morning, Good Afternoon or Good Evening
    currentTime = datetime.datetime.now().hour

    if currentTime < 12:
        greeting = "Good Morning, "
    elif 12 <= currentTime < 18:
        greeting = "Good Afternoon, "
    else:
        greeting = "Good Evening, "

    message = "\n-----\n"+greeting + receiver_name + ".\n"+optional_message + "\n\nFrom: " + local_user +"\n-----\n"
    print("Sending Message: \n",message+"\n")
    message = rsa.encrypt(message.encode(), receiver_key).decode('latin-1')

    data = {"type": "message", "content":message}

    # Tries to send the json payload to the address
    try:
        send_data(client_socket, data)
    except socket.timeout as inst:
        # If the request times out it attempts to resend the data. It moves on to the next address if that fails
        print("Request timed out - Resending Data")
        try:
            send_data(client_socket, data)
        except:
            print("Error, cannot establish connection with current IP, moving on to next address\n\n")
            client_socket.close()
            continue
    except socket.error:
        print("Error with connection - Resending Data")
        try:
            send_data(client_socket, data)
        except:
            print("Error, cannot establish connection with current IP, moving on to next address\n\n")
            client_socket.close()
            continue
    except:
        print("Unknown error occurred, moving on to next IP address\n\n")
        client_socket.close()
        continue

    """
    Receiving a response message
    """
    try:
        receive_data(client_socket, "message")
    except socket.timeout as inst:
        print("Socket timed out, trying again")
        try:
            receive_data(client_socket, "message")
        except:
            print("An Error occurred receiving data from the current IP, moving on to next address\n\n")
            client_socket.close()
            continue
    except:
        print("An error occurred, trying again")
        try:
            receive_data(client_socket, "message")
        except:
            print("An Error occurred receiving data from the current IP, moving on to next address\n\n")
            client_socket.close()
            continue

    """
    Ending the connection with the current receipient as the message has been sent successfully
    """
    data = {"type": "fin"}
    # Tries to send the json payload to the address
    try:
        send_data(client_socket, data)
    except socket.timeout as inst:
        # If the request times out it attempts to resend the data once then will move on to the next address if that fails
        print("Request timed out - Resending Data")
        try:
            send_data(client_socket, data)
        except:
            print("Error, cannot establish connection with current IP, moving on to next address\n\n")
            client_socket.close()
            continue
    except socket.error:
        print("Error with connection - Resending Data")
        try:
            send_data(client_socket, data)
        except:
            print("Error, cannot establish connection with current IP, moving on to next address\n\n")
            client_socket.close()
            continue
    except:
        print("Unknown error occurred, moving on to next IP address\n\n")
        client_socket.close()
        continue

    client_socket.close()

    print("Terminated connection with recipient - " + str(UDP_IP_ADDRESS))