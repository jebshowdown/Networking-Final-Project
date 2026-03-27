from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Util.Padding import pad, unpad
import socket
import sys
from datetime import datetime
import os
import json

def generate_server_keys():
    """Outputs RSA keys if they don't exist"""
    priv_path = "server_private.pem"
    pub_path = "server_public.pem"
    print("Generating server RSA keys...")
    key = RSA.generate(2048)
    with open(priv_path, "wb") as f:
        f.write(key.export_key('PEM'))
    with open(pub_path, "wb") as f:
        f.write(key.publickey().export_key('PEM'))

def server_start() -> socket.socket:
    """
    Purpose: Starts the server and listens, returning the server socket
    Parameters: none
    Returns: server socket
    """
    server_port = 13000
    try:
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # initiate a socket with IPV4
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) # allow port reuse quickly after restart
    except socket.error as error:
        print("Error in connection to socket", error)

    try:
        server_socket.bind(('', server_port)) # bind socket to port
    except socket.error as error:
        print("Socket binding error", error)

    server_socket.listen(5) # start up server, listen with a backlog

    return server_socket # return the server socket

def send_pub_key(connected_socket):
    """
    Purpose: Sends the server's public key as a message to the client
    Parameters: The connected socket
    Returns: None
    """
    with open("server_public.pem", "r") as f:
        ser_pub_key = f.read()
    connected_socket.send(ser_pub_key.encode()) # automatically share public key with client

def recv_pub_key(connected_socket: socket, client: str):
    """
    Purpose: Sends the server's public key as a message to the client
    Parameters: The connected socket
    Returns: None
    """
    with open(f"{client}_public.pem", "w") as f:
        pub_key = connected_socket.recv(1024).decode() # automatically share public key with client
        f.write(pub_key)


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

    
def sym_encrypt(data, sym_key: bytes) -> bytes:
    """
    Purpose: Encrypt data using the symmetric key
    Parameters: data (string or bytes), sym_key (bytes)
    Returns: encrypted data (bytes)
    """
    cipher_aes = AES.new(sym_key, AES.MODE_ECB) # creates a new AES cipher
    if isinstance(data, str):
        data = data.encode('utf-8')
    padded_data = pad(data, AES.block_size) # pads the data
    return cipher_aes.encrypt(padded_data) # encrypts and returns the data in bytes

def sym_decrypt(data: bytes, sym_key: bytes) -> str: 
    """
    Purpose: Decrypt data using the symmetric key
    Parameters: data (bytes), sym_key (bytes)
    Returns: encrypted data (bytes)
    """
    cipher_aes = AES.new(sym_key, AES.MODE_ECB) # creates a new AES cipher
    padded_decrypted = cipher_aes.decrypt(data) # decrypts the data in string
    return unpad(padded_decrypted, AES.block_size).decode('UTF-8') # unpads, decodes, and returns the string

def asym_encrypt(data: bytes, public_key_path: str) -> bytes:
    """
    Purpose: Encrypt the symmetric key using RSA encryption
    Parameters: data (bytes), public_key_path (string)
    Returns: encrypted data (bytes)
    """
    recipient_key = RSA.import_key(open(public_key_path).read()) # imports the public key
    cipher_rsa = PKCS1_OAEP.new(recipient_key) # creates a new RSA cipher
    
    # Encrypt and return raw bytes
    return cipher_rsa.encrypt(data)

def parse_email_info(client: str, connection: socket, sym_key: str) -> None:
    """
    Purpose: parses email info when an email is received by server
    Parameters: connection -> socket: the socket connection
                sym_key -> str: the symmetric key for the server
    Returns: sender -> str: the name of the sending client
            receivers -> str: the names of the receiving client(s)
            time -> str: the time the message was received
            title -> str: the email title
            content_len -> str: the length of the content in bytes
            content -> str: the email content
    """
    email_msg = sym_decrypt(connection.recv(1024), sym_key) # receive email 
    email_parts = email_msg.split("\n") # split email into a list of parts
    sender = email_parts[0].replace("From: ", "") # remove labels from parts to only have the contents
    receivers = email_parts[1].replace("To: ", "")
    time = str(datetime.now())
    title = email_parts[2].replace("Title: ", "")
    content_len = email_parts[3].replace("Content Length: ", "")
    content = "\n".join(email_parts[5:]) # join all remaining parts as they are the email content

    add_to_inbox_list(client, sender, time, title) # add email info to inbox list

    print(f"An email from {sender} is sent to {receivers} has a content length of {content_len}\n") 
    
    return sender, receivers, time, title, content_len, content 

def add_to_inbox_list(client, sender, time, title):
    """
    Purpose: Adds entry to the inbox json database
    Parameters: client -> str: the current client
                sender -> str: the name of the sender
                time -> str: the time of sending
                title -> the title of sent email
    Returns: None
    """
    db_path = f"{client}/{client}_inbox.json"
    os.makedirs(client, exist_ok=True) # Ensure the client directory exists
    if os.path.exists(db_path):
        with open(db_path, 'r') as inbox_file: # check to see if the json file is already populated
            try:
                inbox = json.load(inbox_file) # read the contents of the JSON file
            except json.decoder.JSONDecodeError: # if the JSON is empty, create a new list to populate the file with
                inbox = {}
    else:
        inbox = {} # if no json file exits, start by creating a dictionary

    inbox[str(len(inbox)+1)] = { # add current email to the dictionary
        "sender": sender,
        "time": time,
        "title": title
    }

    with open(db_path, "w") as inbox_file: # create json file if it does not exist, open in write mode
        json.dump(inbox, inbox_file, indent=4) # add the dictionary to the json file 


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
    content = ( # create the email with all relevant info
        "From: " + sender + "\n"
        "To: " + receivers + "\n"
        "Time and Date Received: " + time + "\n"
        "Title: " + title + "\n"
        "Content Length: " + str(content_len) + "\n"
        "Content: \n"
        + content
    )
    
    for client in receivers.split(";"):
        client = client.strip() # Strip whitespaces
        os.makedirs(client, exist_ok=True) # Ensure receiving client directory exists
        with open(f"{client}/{client}_{title}.txt", "w") as f: # saves file in client directory
            f.write(content) # write all email content into the file
        add_to_inbox_list(client, sender, time, title)
    
# ------View Inbox Subprotocol------
def send_inbox(client:str, connection: socket, sym_key: str) -> None:
    """
    Purpose: Creates a string representing the inbox, encrypts it, and sends to client
    Parameters: connection -> socket: the client connection socket
    sym_key: string -> the sym key to encrypt email data
    Returns: None
    """
    with open(f"{client}/{client}_inbox.json", "r") as f:
        inbox = json.load(f)
    inbox_str = "Index  From            DateTime                Title\n" # create inbox header 

    for key, value in inbox:
        inbox_str += f"{0:2}{1:15}{2:36}{3:}\n".format(key, value.get("sender"), value.get("time"), value.get("title")) # add inbox entries incrementally
    connection.send(sym_encrypt(inbox_str.encode(), sym_key)) # send the whole inbox as a table formatted string

    ok_msg = sym_decrypt(connection.recv(16), sym_key) # receive and print ok message from client
    print(ok_msg)

#------View Email Subprotocol------
def send_email_by_index(client: str, connection: socket, sym_key: str) -> None:
    """
    Purpose: Finds an email in file, encrypts it, and sends to client
    Parameters: client -> str: the current client user
    connection -> socket: the client connection socket
    sym_key: string -> the sym key to encrypt email data
    Returns: None
    """
    email_path = f"{client}/{client}_{title}.txt"
    db_path = f"{client}/{client}_inbox.json"

    msg = "The server request email index: "
    connection.send(sym_encrypt(msg.encode("UTF-8"), sym_key)) # send index request message
    index = sym_decrypt(connection.recv(16), sym_key) # receive and decrypt the request

    with open(db_path, "r") as inbox_file: # open the inbox 
        inbox = json.load(inbox_file)

    email_dict = inbox[str(index)] # find the dictionary with given index from inbox
    title = email_dict.get("title") # get the title to search for specific email from files
    file_size = os.path.getsize(email_path)
    
    with open(email_path, "rb") as f: # open file with corresponding title
        while True: # send all email contents 1 kB at a time
            email_contents = f.read(1024)
            if not email_contents:
                connection.sendall(sym_encrypt(b"<<EOF>>", sym_key))
                break
            connection.sendall(sym_encrypt(email_contents, sym_key)) # send file 1Kb at a time



def handle_client(connection):
    """
    Purpose: Handles a single client connection
    Parameters: connection (socket)
    """
    try:
        send_pub_key(connection) # sends server public key from file

        username, password = receive_client_credentials(connection)

        recv_pub_key(connection, username) # receives client public key and saves to file

        if client_login_check(username, password):
            sym_key = get_random_bytes(32) # generate a symmetric key
            encrypted_sym_key = asym_encrypt(sym_key, username + "_public.pem")  # encrypt the symmetric key using the client's public key
            send_sym_key(connection, encrypted_sym_key)
            print_connection_success(username)
        else:
            send_invalid_login(connection, username)
            return # exit client handler so child process terminates
            
        while True:
            menu = "\nSelect an operation:\n" \
            "1) Create and send an email\n" \
            "2) Display the inbox list\n" \
            "3) Display the email contents\n" \
            "4) Terminate the connection\n" \
            "Choice: "
            connection.send(sym_encrypt(menu, sym_key))
            choice = sym_decrypt(connection.recv(1024), sym_key)

            if choice == "1":
                # create and send email
                sender, receivers, time, title, content_len, content = parse_email_info(username, connection, sym_key)
                construct_email_file(sender, receivers, str(time), title, content_len, content)
            elif choice == "2":
                # display inbox subprotocol
                send_inbox(username, connection, sym_key)
            elif choice == "3":
                # display email content subprotocol
                send_email_by_index(username, connection, sym_key)
            elif choice == "4":
                # terminate connection subprotocol
                connection.close()
                print(f"Terminating connection with {username}")
                break # Exit the loop so the child process can terminate gracefully

    except socket.error as error:
        print('Error:', error)
        try:
            connection.close()
        except:
            pass
    finally:
        sys.exit(0) # IMPORTANT: The child process must exit when done with the client!


def main():
    generate_server_keys()
    
    server_socket = server_start()
    print("Server is up and listening for connections on port 13000...")

    while True:
        # Prevent zombie processes: manually reap finished children without blocking
        try:
            while True:
                # WNOHANG prevents waitpid from blocking if no children have finished
                wpid, status = os.waitpid(-1, os.WNOHANG)
                if wpid == 0:
                    break # No more zombie processes to reap
        except OSError:
            pass # No child processes exist yet

        try:
            connection, address = server_socket.accept()
            print(f"Connection accepted from {address}")
            
            pid = os.fork()
            if pid == 0:
                # This is the child process
                server_socket.close() # The child doesn't need the listening socket
                handle_client(connection) # Handles the client. It calls sys.exit(0) at the end.
            else:
                # This is the parent process
                connection.close() # The parent doesn't need to communicate with this connected client, so close it.
                
        except socket.error as error:
            print('Socket accept error:', error)
            break
        except KeyboardInterrupt:
            print("Shutting down the server.")
            break

if __name__ == "__main__":
    main()