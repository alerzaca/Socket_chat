# Simple client-server socket chat app encrypted with openssl

 Features included:

    - Usage of Socket Programming for creating client and server programs
    - Usage of Multi-threading for Full Duplex communication
    - Possibility to connect multiple clients
    - Distinguishing users based on nickname
    - Encryption of all messages

Future improvements:

    - Possibility to create Chat Logs by the server
    - User accounts storage (username, password) and password encryption (hash)


##  How-to: create your own openssl certificate and private key

Both server.crt and server.key need to be created in the same directory as programs 

Private key:
```
$ openssl genrsa -des3 -out server.key 2048
```

Certificate:
```
$ openssl req -key server.key -new -x509 -days 365 -out server.crt
```

## How-to: complie and use

```
$ g++ server.cc -o server -lssl -lcrypto
$ g++ client.cc -o client -lssl -lcrypto
```
Usage:
```
$ ./server <port>
$ ./client <server ip> <server port>
```
