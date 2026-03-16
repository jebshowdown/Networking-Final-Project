# Python Client
import sys
import socket 
import os

def validate_email_fields(title, content):
    # Title must be 100 chars or less
    if len(title) > 100:
        raise ValueError("Title is too long. Maximum is 100 characters.")

    # Content cannot be longer than 1000000 characters
    if len(content) > 1000000:
        raise ValueError("Content is too long. Maximum is 1000000 characters.")


def build_email_message(sender, receivers, title, content):
   
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
                    client_socket.send(email_message.encode('UTF-8')) # sends email to server 

                    print("The message is sent to the server.")

                except FileNotFoundError:
                    print("File not found.")
                except ValueError as e:
                    print("Email error:", e)   
                
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