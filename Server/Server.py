from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Util.Padding import pad, unpad
import socket
import sys
from datetime import date, datetime
import json

def server_start() -> socket:
    """
    Purpose: Starts the server and listens, if a connection is made it returns the connection socket
    Parameters: none
    Returns: socket
    """
    server_port = 13000
    try:
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # initiate a socket with IPV4
    except socket.error as error:
        print("Error in connection to socket", error)

    try:
        server_socket.bind((" ", server_port)) # bind socket to port
    except socket.error as error:
        print("Socket binding error", error)

    server_socket.listen(1) # start up server

    try:
        connected_socket, address = server_socket.accept() # accept a socket connection
    except socket.error as error:
        print("An error occured", error)

    return connected_socket # return the connected socket

def send_pub_key(connected_socket):
    """
    Purpose: Sends the server's public key as a message to the client
    Parameters: The connected socket
    Returns: None
    """
    with open("server_public.pem", "r") as f:
        ser_pub_key = f.read()
    connected_socket.send(ser_pub_key.encode()) # automatically share public key with client


def generate_sym_key() -> bytes:
    """
    Purpose: Generate a symmetric key for a user
    Parameters: None
    Returns: symmetric key (bytes)
    """
    return get_random_bytes(32)

def load_user_passwords():

    """
    Purpose: Loads usernames and passwords 
    Parameters: None
    Returns: dictionary of usernames and passwords
    """
    with open("user_pass.json", "r") as f:
        user_data = json.load(f)

    return user_data

def client_login_check(username, password):
    """
    Purpose: Checks if the client's username and password match 
    Parameters: username (str), password (str)
    Returns: True if login is correct, otherwise False
    """
    user_data = load_user_passwords()

    if username in user_data and user_data[username] == password:
        return True

    return False
def send_sym_key(connection, encrypted_sym_key):
    """
    Purpose: Sends the encrypted symmetric key to the client
    Parameters: connection (socket), encrypted_sym_key (bytes)
    Returns: None
    """
    connection.send(encrypted_sym_key)

def print_connection_success(username):
    """
    Purpose: Prints the required success message on the server
    Parameters: username (str)
    Returns: None
    """
    print("Connection Accepted and Symmetric Key Generated for client: " + username)

def send_invalid_login(connection, username):
    """
    Purpose: it sends the invalid login message to the client, prints the required
             server message, and closes the connection
    Parameters: connection (socket), username (str)
    Returns: None
    """
    connection.send("Invalid username or password".encode("utf-8"))
    print(f"The received client information: {username} is invalid (Connection Terminated).")
    connection.close()

def receive_client_credentials(connection):
    """
    Purpose: Receives the encrypted username and password from the client,
             decrypts them using the server private key, and returns both
    Parameters: connection (socket)
    Returns: username (str), password (str)
    """
    encrypted_data = connection.recv(1024)

    with open("server_private.pem", "rb") as f:
        server_private_key = RSA.import_key(f.read())

    cipher_rsa = PKCS1_OAEP.new(server_private_key)
    decrypted_data = cipher_rsa.decrypt(encrypted_data).decode("utf-8")

    username, password = decrypted_data.split("\n")
    return username, password

def terminate_connection(connection, username):
    """
    Purpose: Terminates the connection with the client 
    Parameters: connection (socket), username (str)
    Returns: None
    """
    print(f"Terminating connection with {username}.")
    connection.close()
    
def test_generate_sym_key():
    """
    Purpose: Test the generate_sym_key function
    Parameters: None
    Returns: None
    """
    sym_key = generate_sym_key()
    print(sym_key.hex())
    assert len(sym_key) == 32, f"Expected 32 bytes, got {len(sym_key)}"
    print("test_generate_sym_key passed successfully!")

def sym_encrypt(data: str, sym_key: bytes) -> bytes:
    cipher_aes = AES.new(sym_key, AES.MODE_ECB) # creates a new AES cipher
    padded_data = pad(data.encode('utf-8'), AES.block_size) # pads the data
    return cipher_aes.encrypt(padded_data) # encrypts and returns the data in bytes

def sym_decrypt(data: bytes, sym_key: bytes) -> str: 
    cipher_aes = AES.new(sym_key, AES.MODE_ECB) # creates a new AES cipher
    padded_decrypted = cipher_aes.decrypt(data) # decrypts the data in string
    return unpad(padded_decrypted, AES.block_size).decode('UTF-8') # unpads, decodes, and returns the string


def parse_email_info(connection: socket, sym_key: str) -> None:
    """
    Purpose: parses email info when an email is received by server
    Parameters: connection -> socket: the socket connection
                sym_key -> str: the symmetric key for the server
    Returns: sender -> str: the name of the sending client
            title -> str: the email title
            receivers -> str: the names of the receiving client(s)
            content_len -> str: the length of the content in bytes
            content -> str: the email content
    """
    email_msg = sym_decrypt(connection.recv(1024).decode("UTF-8"), sym_key)
    email_parts = email_msg.split("\n")
    sender = email_parts[0].replace("From: ", "")
    receivers = email_parts[1].replace("To: ", "")
    time = datetime.now()
    title = email_parts[2].replace("Title: ", "")
    content_len = email_parts[3].replace("Content Length: ", "")
    content = "\n".join(email_parts[5:])

    print(f"An email from {sender} is sent to {receivers} has a content length of {content_len}\n")
    return sender, receivers, time, title, content_len, content

def construct_email_file(sender, receivers, time, title, content_len, content):
    """
        Purpose: Creates and saves email record to text file
    Parameters: sender -> str: the name of the sending client
            title -> str: the email title
            receivers -> str: the names of the receiving client(s)
            content_len -> str: the length of the content in bytes
            content -> str: the email content
    Returns: None
    """
    content = (
        "From: " + sender + "\n"
        "To: " + receivers + "\n"
        "Time and Date Received: " + time + "\n"
        "Title: " + title + "\n"
        "Content Length: " + str(content_len) + "\n"
        "Content: \n"
        + content
    )
    
    with open(f"{sender}/{sender}_{title}.txt", "w") as f: # saves file in client directory **change name if needed
        f.write(content)
    

# ---- Asymmetric Encryption (RSA) Helper Function ----
# Purpose: Encrypt the symmetric key using RSA encryption
# Input: data (bytes), public_key_path (string)
# Output: encrypted data (bytes)
# -----------------------------------------------------
def asym_encrypt(data: bytes, public_key_path: str) -> bytes:
    recipient_key = RSA.import_key(open(public_key_path).read()) # imports the public key
    cipher_rsa = PKCS1_OAEP.new(recipient_key) # creates a new RSA cipher
    
    # Encrypt and return raw bytes
    return cipher_rsa.encrypt(data)

def main():
    connection = server_start()
    send_pub_key(connection)

    username, password = receive_client_credentials(connection)

    if client_login_check(username, password):
        sym_key = generate_sym_key() # generate a symmetric key
        encrypted_sym_key = asym_encrypt(sym_key, username + "_public.pem")  # encrypt the symmetric key using the client's public key
        send_sym_key(connection, encrypted_sym_key)
        print_connection_success(username)
        return
    
    else:
        send_invalid_login(connection, username)
        return

if __name__ == "__main__":
    main()