from Crypto.Random import get_random_bytes
import socket
import sys
from datetime import date, datetime

def server_start():
    server_port = 13000
    try:
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    except socket.error as error:
        print("Error in connection to socket", error)

    try:
        server_socket.bind((" ", server_port))
    
    except socket.error as error:
        print("Socket binding error", error)

    server_socket.listen(1) # start up server


    try:
        connected_socket, address = server_socket.accept()
        with open("server_public.pem", "r") as f:
            ser_pub_key = f.read()
        
        connected_socket.send(ser_pub_key.encode()) # automatically share public key with client

    except socket.error as error:
        print("An error occured", error)
        
def generate_sym_key() -> bytes:
    """
    Purpose: Generate a symmetric key for a user
    Parameters: None
    Returns: symmetric key (bytes)
    """
    return get_random_bytes(32)


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

def main():
    test_generate_sym_key() # Run the test function for generate_sym_key
    return

if __name__ == "__main__":
    main()