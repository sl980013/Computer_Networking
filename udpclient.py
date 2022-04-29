import socket
import os
import json
import rsa
import datetime
import zlib


# Uses CRC32 to calculate a checksum for our data to be sent
# takes in json data and compares the checksum in the json object with the calculated checksum
# checksum is performed on the type and content of the json
def checksum_calculator(data):
    name = data.get("type")
    content = data.get("content")
    if name is None:
        name = ""
    if content is None:
        content = ""
    checksum_sequence = name + content

    checksum = zlib.crc32(bytes(checksum_sequence, "utf-8"))
    return checksum


def send_data(sock, jsonData):

    # calculates checksum and puts it in json object
    checksumVal = checksum_calculator(jsonData)
    # append checksum to json
    jsonData['checksum'] = checksumVal

    jsonData = json.dumps(jsonData)

    # Attempts to send the data to the recipient
    sock.sendto(jsonData.encode(), UDP_ADDRESS)

    try:
    # After every message is sent there should be an ACK packet sent back to confirm it's arrival,
    # Else it will attempt to resend the data one more time before moving on to the next address
        data, server = sock.recvfrom(4096)
        jsonObj = json.loads(data)
        jpacket = jsonObj.get("type")
    # if an acknowledgement message is received then we know the data reached the recipient correctly
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

    jsonObj = json.loads(data)

    # Checks if the received packet has a checksum as it was optional for this implementation
    # if the checksums do not match then it will raise an exception
    if jsonObj.get("checksum") is not None:
        if checksum_calculator(jsonObj) != int(jsonObj.get("checksum")):
            print("Checksums do not match, need the packet resent")
            raise Exception()
        else:
            print("Checksums match")

    jpacket = jsonObj.get("type")

    print("Packet Type Received: ", jpacket)

    if jpacket != expected_type:
        print("Incorrect packet type received")
        raise Exception()

    if jpacket == "recipient_public_key":
        global recipientKey
        recipientKey =  rsa.PublicKey.load_pkcs1(jsonObj.get("content").encode())
    elif jpacket == "recipient_username":
        global recipientUsername
        recipientUsername = rsa.decrypt(jsonObj.get("content").encode('latin-1'), privateKey).decode()

    elif jpacket == "message":
        print(rsa.decrypt(jsonObj.get("content").encode('latin-1'), privateKey).decode())

    # sends an ACK packet back to confirm the data was received
    data = {"type": "ack"}
    jsonData = json.dumps(data)
    sock.sendto(jsonData.encode(), UDP_ADDRESS)



local_user = os.getlogin()

## Generates a new RSA private and public key
publicKey, privateKey = rsa.newkeys(2048)


# Defining global variables
global recipientKey
global recipientUsername





receiver_list = ""
while receiver_list == "":
    receiver_list = str(input("Enter your list of IP addresses you want to send greetings to with commas separating the addresses (e.g '127.0.0.1, 127.0.0.2, 127.0.0.3' ):\n"))

receiver_list = receiver_list.replace(" ", "")
receiver_list = receiver_list.split(",")
print(receiver_list)

# This custom Message is optional and will be taken at the start of program execution
customMessage = str(input("Please enter your custom message (optional): "))




# Attempts to send the greeting to each IP address that the user entered
for i, receiver in enumerate(receiver_list):

###### Creating socket for current IP

    # Change the IP Address to the list of IPs
    UDP_IP_ADDRESS = receiver
    try:
        socket.inet_aton(UDP_IP_ADDRESS)
        # IP is legal if passes
    except socket.error:
        # Not legal
        print("IP is not valid")
        # continue, used to end the for loop iteration for the IP entered
        continue

    # Setting the Receiver address and establishing a socket connection, setting a timeout to 1 second
    UDP_PORT_NO = 12001
    UDP_ADDRESS = (UDP_IP_ADDRESS, UDP_PORT_NO)
    socket.setdefaulttimeout(1)
    clientSock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)



###### Synchronize packet for initiating connection
    print("\n\nInitialising connection")
    data = {"type": "sync"}

    # Tries to send the json payload to the address
    try:
        send_data(clientSock, data)
    except socket.timeout as inst:
        # If the request times out it attempts to resend the data once then will move on to the next address if that fails
        print("Request timed out - Resending Data")
        try:
            send_data(clientSock, data)
        except:
            print("Error, cannot establish connection with current IP, moving on to next address\n\n")
            clientSock.close()
            continue
    except socket.error:
        print("Error with connection - Resending Data")
        try:
            send_data(clientSock, data)
        except:
            print("Error, cannot establish connection with current IP, moving on to next address\n\n")
            clientSock.close()
            continue
    except:
        print("Unknown error occurred, moving on to next IP address\n\n")
        clientSock.close()
        continue


###### Exchange Public keys between receiver and sender
    print("Exchanging public keys")
    # Converts public key to PEM format as bytes then decodes it to string
    publicKey_packet = publicKey.save_pkcs1().decode()
    data = {"type": "sender_public_key", "content": publicKey_packet }

    # Tries to send the json payload to the address
    try:
        send_data(clientSock, data)
    except socket.timeout as inst:
        # If the request times out it attempts to resend the data once then will move on to the next address if that fails
        print("Request timed out - Resending Data")
        try:
            send_data(clientSock, data)
        except:
            print("Error, cannot establish connection with current IP, moving on to next address\n\n")
            clientSock.close()
            continue
    except socket.error:
        print("Error with connection - Resending Data")
        try:
            send_data(clientSock, data)
        except:
            print("Error, cannot establish connection with current IP, moving on to next address\n\n")
            clientSock.close()
            continue
    except:
        print("Unknown error occurred, moving on to next IP address\n\n")
        clientSock.close()
        continue


    try:
        receive_data(clientSock, "recipient_public_key")
    except socket.timeout as inst:
        print("Socket timed out, trying again")
        try:
            receive_data(clientSock, "recipient_public_key")
        except:
            print("An Error occurred receiving data from the current IP, moving on to next address\n\n")
            clientSock.close()
            continue
    except:
        print("An error occurred, trying again")
        try:
            receive_data(clientSock, "recipient_public_key")
        except:
            print("An Error occurred receiving data from the current IP, moving on to next address\n\n")
            clientSock.close()
            continue




###### Sending a request for the recipient username
    print("Asking for recipient username")
    data = {"type": "request_username"}
    # Tries to send the json payload to the address
    try:
        send_data(clientSock, data)
    except socket.timeout as inst:
        # If the request times out it attempts to resend the data once then will move on to the next address if that fails
        print("Request timed out - Resending Data")
        try:
            send_data(clientSock, data)
        except:
            print("Error, cannot establish connection with current IP, moving on to next address\n\n")
            clientSock.close()
            continue
    except socket.error:
        print("Error with connection - Resending Data")
        try:
            send_data(clientSock, data)
        except:
            print("Error, cannot establish connection with current IP, moving on to next address\n\n")
            clientSock.close()
            continue
    except:
        print("Unknown error occurred, moving on to next IP address\n\n")
        clientSock.close()
        continue


#### Receiving recipient username
    try:
        receive_data(clientSock, "recipient_username")
    except socket.timeout as inst:
        print("Socket timed out, trying again")
        try:
            receive_data(clientSock, "recipient_username")
        except:
            print("An Error occurred receiving data from the current IP, moving on to next address\n\n")
            clientSock.close()
            continue
    except:
        print("An error occurred, trying again")
        try:
            receive_data(clientSock, "recipient_username")
        except:
            print("An Error occurred receiving data from the current IP, moving on to next address\n\n")
            clientSock.close()
            continue

    print(recipientUsername)

###### Sending the greeting message

    # Checks time to put in correct greeting of Good Morning, Good Afternoon or Good Evening
    currentTime = datetime.datetime.now().hour

    if currentTime < 12:
        greeting = "Good Morning "
    elif 12 <= currentTime < 18:
        greeting = "Good Afternoon "
    else:
        greeting = "Good Evening "

    message = "\n-----\n"+greeting + recipientUsername+ ".\n"+customMessage + "\n\nFrom: " +local_user+"\n-----\n"


    print("Sending Message: \n",message+"\n")
    message = rsa.encrypt(message.encode(), recipientKey).decode('latin-1')

    data = {"type": "message", "content":message}

    # Tries to send the json payload to the address
    try:
        send_data(clientSock, data)
    except socket.timeout as inst:
        # If the request times out it attempts to resend the data once then will move on to the next address if that fails
        print("Request timed out - Resending Data")
        try:
            send_data(clientSock, data)
        except:
            print("Error, cannot establish connection with current IP, moving on to next address\n\n")
            clientSock.close()
            continue
    except socket.error:
        print("Error with connection - Resending Data")
        try:
            send_data(clientSock, data)
        except:
            print("Error, cannot establish connection with current IP, moving on to next address\n\n")
            clientSock.close()
            continue
    except:
        print("Unknown error occurred, moving on to next IP address\n\n")
        clientSock.close()
        continue

#### Receiving a response message
    try:
        receive_data(clientSock, "message")
    except socket.timeout as inst:
        print("Socket timed out, trying again")
        try:
            receive_data(clientSock, "message")
        except:
            print("An Error occurred receiving data from the current IP, moving on to next address\n\n")
            clientSock.close()
            continue
    except:
        print("An error occurred, trying again")
        try:
            receive_data(clientSock, "message")
        except:
            print("An Error occurred receiving data from the current IP, moving on to next address\n\n")
            clientSock.close()
            continue

##### Ending the connection with the current receipient as the message has been sent successfully
    data = {"type": "fin"}
    # Tries to send the json payload to the address
    try:
        send_data(clientSock, data)
    except socket.timeout as inst:
        # If the request times out it attempts to resend the data once then will move on to the next address if that fails
        print("Request timed out - Resending Data")
        try:
            send_data(clientSock, data)
        except:
            print("Error, cannot establish connection with current IP, moving on to next address\n\n")
            clientSock.close()
            continue
    except socket.error:
        print("Error with connection - Resending Data")
        try:
            send_data(clientSock, data)
        except:
            print("Error, cannot establish connection with current IP, moving on to next address\n\n")
            clientSock.close()
            continue
    except:
        print("Unknown error occurred, moving on to next IP address\n\n")
        clientSock.close()
        continue



    clientSock.close()

    print("Terminated connection with recipient - " + str(UDP_IP_ADDRESS))