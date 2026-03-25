# Python ClientZ
import sys
import socket 
import os
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Util.Padding import pad, unpad

def validate_email_fields(title, content):
    # Title must be 100 chars or less
    if len(title) > 100:
        raise ValueError("Title is too long. Maximum is 100 characters.")

    # Content cannot be longer than 1000000 characters
    if len(content) > 1000000:
        raise ValueError("Content is too long. Maximum is 1000000 characters.")


def build_email_message(sender, receivers, title, content) -> str:
   
    validate_email_fields(title, content)  # check that title and content follow the rules
    content_length = len(content) # counts how many characters are in the content

    # builds email format
    email_message = (
        "From: " + sender + "\n"
        "To: " + receivers + "\n"
        "Title: " + title + "\n"
        "Content Length: " + str(content_length) + "\n"
        "Content: \n"
        + content
    )

    return email_message

# ---- Asymmetric Encryption (RSA) Helper Function ----
# Purpose: Encrypt the username and password using RSA 
#          encryption
# Input: data (string), public_key_path (string)
# Output: encrypted data (bytes)
# -----------------------------------------------------
def asym_encrypt(data: str, public_key_path: str) -> bytes:
    recipient_key = RSA.import_key(open(public_key_path).read()) # imports the public key
    cipher_rsa = PKCS1_OAEP.new(recipient_key) # creates a new RSA cipher
    
    # Encrypt and return raw bytes
    return cipher_rsa.encrypt(data.encode())

# ---- Symmetric Encryption (AES-ECB) Helper Function ----
# Purpose: Encrypt using AES encryption the email message
# Input: data (string), key (bytes)
# Output: encrypted data (bytes)
# --------------------------------------------------------
def sym_encrypt(data: str, sym_key: bytes) -> bytes:
    cipher_aes = AES.new(sym_key, AES.MODE_ECB) # creates a new AES cipher
    padded_data = pad(data.encode(), AES.block_size) # pads the data
    return cipher_aes.encrypt(padded_data) # encrypts and returns the data in bytes

def sym_decrypt(data: bytes, sym_key: bytes) -> str: 
    cipher_aes = AES.new(sym_key, AES.MODE_ECB) # creates a new AES cipher
    padded_decrypted = cipher_aes.decrypt(data) # decrypts the data in string
    return unpad(padded_decrypted, AES.block_size).decode() # unpads, decodes, and returns the string

def send_user_credentials(connection):
    """
    Purpose: Prompts user for credentials, encrypts and sends them
    Parameters: connection -> socket: the client connection socket
    Returns: Username -> str: the client's username
             Password -> str: the client's password
    """
    username = input("Enter the Username: ") # print username prompt and wait for input
    password = input("Enter the password: ") # receive prompt for password
    
    # Combine the username and password into a single string
    user_credentials = username + " " + password
    # Encrypt the combined username and password
    with open("server_public.pem", "r") as f:
        pub_key = f.read()
    encrypted_user_credentials = asym_encrypt(user_credentials, pub_key)
    # Send the encrypted username and password to the server
    connection.send(encrypted_user_credentials)
    return username, password


def client():
    server_name = str(input("Enter the server IP or name: ")) # switch to ipv4 of another computer on the network to transfer between computers
    server_port = 13000
    
    try:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # create a socket
        client_socket.connect((server_name,server_port)) # connect to the server
        
        with open("server_public.pem", "w") as f:
            pub_key = (client_socket.recv(1024).decode())
            f.write(pub_key)

        username, password = send_user_credentials(client_socket)

        # Decrypt the server response (sym_key), encrypt and send OK message
        sym_key = sym_decrypt(client_socket.recv(1024).decode(), username + "_public.pem")
        msg = 'OK'
        client_socket.send(sym_encrypt(msg.encode(), sym_key))

        # Check if the client received "Invalid username or password.\nTerminating" from the server
        if client_socket.recv(1024).decode() == "Invalid username or password.\nTerminating":
            print("Invalid username or password.")
            client_socket.close()
            sys.exit(1)

    except socket.error as e:
        print('Error in client socket creation:',e)
        client_socket.close()
        sys.exit(1)    

    while True:

        try:
            choice = str(input()) # get the choice from the user
            client_socket.send(sym_encrypt(choice.encode(), sym_key)) # send choice to server
            server_response = sym_decrypt(client_socket.recv(1024).decode(), sym_key)
            print(server_response) # TODO: Remove this line later, it's just for testing

            if choice == '1':
                # send email protocol
                try:
                    receivers = input("Enter destinations (separated by ;): ")
                    title = input("Enter title: ")
    
                    file_choice = input("Would you like to load contents from a file?(Y/N) ").strip().upper() # Asks if the user wants to type the message or load it from a file

                    if file_choice == 'Y':
                        file_name = input("Enter filename: ")
                        with open(file_name, "r") as f:
                            content = f.read()
                    else:
                        content = input("Enter message contents: ")

                    email_message = build_email_message(username, receivers, title, content) #build email format 
                    client_socket.send(sym_encrypt(email_message.encode(), sym_key)) # sends email to server 

                    print("The message is sent to the server.")

                except FileNotFoundError:
                    print("File not found.")
                except ValueError as e:
                    print("Email content error:", e)
                
            elif choice == '2':
                # inbox display subprotocol
                print(sym_decrypt(client_socket.recv(2048).decode(), sym_key))
                ok_msg = "OK"
                client_socket.send(sym_encrypt(ok_msg.encode(), sym_key))

            elif choice == '3':
                # Display email contents subprotocol
                index_choice = input(sym_decrypt(client_socket.recv(64).decode(), sym_key)) # get index of needed email from user
                client_socket.send(sym_encrypt(index_choice.encode(), sym_key)) # send index
                print(sym_decrypt(client_socket.recv(2048).decode(), sym_key)) # print the email saved at said index

            elif choice == '4':
                print("The connection is terminated with server")
                sys.exit(1)

        except socket.error as e:
            print('Error:',e)
            client_socket.close()
            sys.exit(1)

client()


# # Test for building email
# try:
#     test_email = build_email_message(
#         "client1",
#         "client2;client3",
#         "TestwefweFWEfgw    EG  EwRGWfgesfWSEFwsefWEFwegwer qhhtqwrehwrthgwrtghwrstgrstghwrtstghwsrthwrtsfhrgfhwtrhjgergetrghwerth",
#         "Hello team"
#     )

#     print(test_email)

# except ValueError as e:
#     print("Email error:", e)