# Python Socket File Transfer

A client-server networking project built in Python that allows files to be securely transferred between two machines over a network using TCP sockets and asymmetric encryption.

## Features

* Client-server architecture using Python sockets
* File transfer over TCP
* Secure communication using asymmetric encryption
* Handles file metadata and transfer data
* Supports communication between networked machines

## Technologies

* Python
* TCP/IP
* Socket Programming
* Asymmetric Encryption

## How It Works

1. The server starts and listens for incoming TCP connections.
2. A client connects to the server.
3. The client and server establish a secure connection using asymmetric encryption.
4. The requested file is transferred through the socket.
5. The receiving side reconstructs and saves the file.

## Project Purpose

This project was created to practice socket programming, client-server architecture, file I/O, and secure network communication in Python.
