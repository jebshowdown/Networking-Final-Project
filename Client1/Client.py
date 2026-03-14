# Python Client
import sys
import socket 
import os

def client():
    server_name = str(input("Enter the server IP or name: ")) # switch to ipv4 of another computer on the network to transfer between computers
    server_port = 13000
    
    try:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((server_name,server_port))
        username = input(client_socket.recv(256).decode('UTF-8')) # print username prompt and wait for input

        # *encrypt username and password before sending*

        client_socket.send(username.encode('UTF-8')) # send the username
        password = input(client_socket.recv(64).decode()) # receive prompt for password
        client_socket.send(password.encode()) # send the password to the server

    except socket.error as e:
        print('Error in client socket creation:',e)
        sys.exit(1)    

    while True:

        try:
            choice_msg = client_socket.recv(64).decode('UTF-8') # recieve choice prompt or username/password error message
            if choice_msg == "Invalid username or password.\nTerminating": # terminate if the username is incorrect
                print(choice_msg)
                sys.exit(1)

            choice = str(input(choice_msg)) # get the choice from the user
            client_socket.send(choice.encode('UTF-8')) # send choice to server

            if choice == '1':
                pass #create and send email subprotocol
            elif choice == '2':
                pass #inbox display subprotocol
            elif choice == '3':
                pass #Display email contents subprotocol
            elif choice == '4':
                pass #Terminate program subprotocol

        except socket.error as e:
            print('Error:',e)
            client_socket.close()
            sys.exit(1)

client()