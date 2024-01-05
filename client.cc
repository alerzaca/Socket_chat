#include <iostream>
#include <cstring>
#include <cstdlib>
#include <unistd.h>
#include <thread>
#include <arpa/inet.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

class Client {
private:
    int clientSocket;
    sockaddr_in serverAddr;

    SSL *ssl;

public:
    std::string username;

    // konstruktor - utworzenie instancji klienta
    Client(const char* serverIP, int port) {
        // Initialize OpenSSL
        SSL_library_init();
        SSL_load_error_strings();

        clientSocket = socket(AF_INET, SOCK_STREAM, 0);
        if (clientSocket == -1) {
            perror("Error creating socket");
            exit(EXIT_FAILURE);
        }

        memset(&serverAddr, 0, sizeof(serverAddr));
        serverAddr.sin_family = AF_INET;
        serverAddr.sin_addr.s_addr = inet_addr(serverIP);
        serverAddr.sin_port = htons(port);

        if (connect(clientSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) == -1) {
            perror("Error connecting to server");
            exit(EXIT_FAILURE);
        }

        // Create a new SSL context
        SSL_CTX *sslContext = SSL_CTX_new(SSLv23_client_method());
        if (!sslContext) {
            ERR_print_errors_fp(stderr);
            exit(EXIT_FAILURE);
        }

        // Create a new SSL connection state
        ssl = SSL_new(sslContext);
        if (!ssl) {
            ERR_print_errors_fp(stderr);
            exit(EXIT_FAILURE);
        }

        // Set the socket for the SSL connection
        SSL_set_fd(ssl, clientSocket);

        // Perform the SSL handshake
        if (SSL_connect(ssl) <= 0) {
            ERR_print_errors_fp(stderr);
            exit(EXIT_FAILURE);
        }

        // wprowadzenie nazwy użytkownika
        std::cout << "Enter your username: ";
        std::cin >> username;
        int usernameLength = username.size();
    
        // to do: weryfikacja czy nazwy się nie dublują -> odebrać z servera clientUsernames i przeszukać

        // wysłanie nazwy do serwera
        send(clientSocket, &usernameLength, sizeof(usernameLength), 0);
        send(clientSocket, username.c_str(), username.size(), 0);
        std::cout << "Connected to server with username: " << username << std::endl;

        // thread - receiveMessages działa ciągle
        std::thread(&Client::receiveMessages, this).detach();
    }

    // wysłanie wiadomości do serwera
    void sendMessage(const char* message) {
        // Use SSL_write for encryption
        SSL_write(ssl, message, strlen(message));
    }

    void receiveMessages() {
        char buffer[1024];
        while (true) {
            memset(buffer, 0, sizeof(buffer));
            // Use SSL_read for decryption
            int bytesRead = SSL_read(ssl, buffer, sizeof(buffer));
            
            if (bytesRead > 0) {
                std::cout << buffer << std::endl;
            }
        }
    }

    // destruktor - zamknięcie klienta
    ~Client() {
        // Clean up OpenSSL
        SSL_free(ssl);

        // to do: wyświetlić informacje o opuszczeniu servera
        // wysłać informacje "Użytkownik xyz opuszcza server"
        close(clientSocket);
    }
};

int main(int argc, char *argv[]) {
    if (argc != 3) {
        std::cerr << "Usage: " << argv[0] << " <server_ip> <server_port>" << std::endl;
        return EXIT_FAILURE;
    }

    const char* SERVER_IP = argv[1];
    int port = std::stoi(argv[2]);

    Client client(SERVER_IP, port);

    char message[1024];

    while (true) {
        std::cin.getline(message, sizeof(message));

        client.sendMessage(message);

        memset(message, 0, sizeof(message));
        std::cout << std::flush;
    }

    return 0;
}
