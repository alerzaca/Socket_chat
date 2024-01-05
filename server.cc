#include <iostream>
#include <cstring>
#include <cstdlib>
#include <unistd.h>
#include <vector>
#include <thread>
#include <unordered_map>
#include <arpa/inet.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#define MAX_CLIENTS 5

class Server {
private:
    int serverSocket;
    sockaddr_in serverAddr;
    sockaddr_in clientAddr;
    socklen_t clientAddrLen;

    std::vector<int> clientSockets;
    std::unordered_map<int, std::string> clientUsernames;

    SSL_CTX *sslContext;
public:
    // konstruktor - utworzenie serwera
    Server(int port) {
        // Initialize OpenSSL
        SSL_library_init();
        SSL_load_error_strings();

        //  AF_INET - ip oraz port
        //  SOCK_STREAM - typ gniazda zorientowany na połączenie
        serverSocket = socket(AF_INET, SOCK_STREAM, 0);
        if (serverSocket == -1) {
            perror("Error creating socket");
            exit(EXIT_FAILURE);
        }

        memset(&serverAddr, 0, sizeof(serverAddr)); // uzupełnia addr zerami
        serverAddr.sin_family = AF_INET;
        serverAddr.sin_addr.s_addr = INADDR_ANY;
        serverAddr.sin_port = htons(port); // int -> network byte order

        // wyłapanie błędów w bind() oraz listen()
        if (bind(serverSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) == -1) {
            perror("Error binding");
            exit(EXIT_FAILURE);
        }

        if (listen(serverSocket, MAX_CLIENTS) == -1) {
            perror("Error listening");
            exit(EXIT_FAILURE);
        }

        std::cout << "Server listening on port " << port << std::endl;

        // Create a new SSL context
        sslContext = SSL_CTX_new(SSLv23_server_method());
        if (!sslContext) {
            ERR_print_errors_fp(stderr);
            exit(EXIT_FAILURE);
        }

        // Load server certificate and private key
        // pass: 1234
        if (SSL_CTX_use_certificate_file(sslContext, "server.crt", SSL_FILETYPE_PEM) <= 0 ||
            SSL_CTX_use_PrivateKey_file(sslContext, "server.key", SSL_FILETYPE_PEM) <= 0) {
            ERR_print_errors_fp(stderr);
            exit(EXIT_FAILURE);
        }
    }

    void acceptConnections() {
        for (int i = 0; i < MAX_CLIENTS; ++i) {
            clientAddrLen = sizeof(clientAddr);
            int clientSocket = accept(serverSocket, (struct sockaddr*)&clientAddr, &clientAddrLen);          
            if (clientSocket == -1) {
                perror("Error accepting connection");
                exit(EXIT_FAILURE);
            }

            // create SSL instance for the accepted connection
            SSL *ssl = SSL_new(sslContext);
            SSL_set_fd(ssl, clientSocket);

            // Perform the SSL handshake
            if (SSL_accept(ssl) <= 0) {
                ERR_print_errors_fp(stderr);
                exit(EXIT_FAILURE);
            }

            // odebranie nazwy użytkownika z socketu
            char username[1024];
            int usernameLength;

            recv(clientSocket, &usernameLength, sizeof(usernameLength), 0);
            recv(clientSocket, username, usernameLength, 0);
            username[usernameLength] = '\0';

            // ustawienie nazwy użytkownika
            clientUsernames[clientSocket] = username;
            clientSockets.push_back(clientSocket);
            std::cout << "Client " << username << " connected" << std::endl;

            // thread - handleClientMessages działa ciągle
            std::thread(&Server::handleClientMessages, this, clientSocket, ssl).detach();
        }
    }

    void broadcastMessage(int senderSocket, SSL *senderSSL, const char* message) {
        for (int i = 0; i < clientSockets.size(); ++i) {
            if (clientSockets[i] != senderSocket) {
                // Use SSL_write for encryption
                SSL_write(SSL_new(sslContext), message, strlen(message));
            }
        }
    }

    void handleClientMessages(int clientSocket, SSL *ssl) {
        char buffer[1024];
        while (true) {
            // Use SSL_read for decryption
            int bytesRead = SSL_read(ssl, buffer, sizeof(buffer));

            if (bytesRead > 0) {
                std::string username = clientUsernames[clientSocket];
                std::cout << username << ": " << buffer << std::endl;
                
                // Use SSL_write for encryption
                broadcastMessage(clientSocket, ssl, (username + ": " + std::string(buffer)).c_str());
            }
            memset(buffer, 0, sizeof(buffer));
        }
    }

    // destruktor - zamknięcie serwera
    ~Server() {
        // Clean up OpenSSL
        SSL_CTX_free(sslContext);

        for (int i = 0; i < clientSockets.size(); ++i) {
            // to do: informacja o zamknięciu serwera, c++ mi nie pozwala...
            close(clientSockets[i]);
        }
        close(serverSocket);
        exit(0);
    }
};

int main(int argc, char *argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <port>" << std::endl;
        return EXIT_FAILURE;
    }

    int port = std::stoi(argv[1]);
    Server server(port);
    server.acceptConnections();

    return 0;
}
