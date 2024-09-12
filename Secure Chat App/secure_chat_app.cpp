#include <iostream>
#include <cstdlib>
#include <cstring>
#include <cstdio>
#include <unistd.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <fcntl.h>

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/opensslv.h>

using namespace std;

// Define constants
#define SERVER_PORT 8080
#define MAX_SIZE 1024

// Function to handle errors
void error_handler(const char* err_msg) {
    cerr << err_msg << endl;
    exit(EXIT_FAILURE);
}

// Initialize OpenSSL
void initialize_openssl() {
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
}

int setSocketNonBlocking(int socket_fd) {
    int flags = fcntl(socket_fd, F_GETFL, 0);
    if (flags == -1) {
        perror("fcntl");
        return -1;
    }

    if (fcntl(socket_fd, F_SETFL, flags | O_NONBLOCK) == -1) {
        perror("fcntl");
        return -1;
    }

    return 0;
}

int setSocketBlocking(int socket_fd) {
    int flags = fcntl(socket_fd, F_GETFL, 0);
    if (flags == -1) {
        perror("fcntl");
        return -1;
    }

    flags &= ~O_NONBLOCK; // Clear the O_NONBLOCK flag
    if (fcntl(socket_fd, F_SETFL, flags) == -1) {
        perror("fcntl");
        return -1;
    }

    return 0;
}

// Generate a cookie for DTLS handshake
int generate_cookie(SSL *ssl, unsigned char *cookie, unsigned int *cookie_len) {
    memcpy(cookie, "cookie", 6);
    *cookie_len = 6;
    return 1;
}

// Verify the cookie received in DTLS handshake
int verify_cookie(SSL *ssl, const unsigned char *cookie, unsigned int cookie_len) {
    return 1;
}

// Cleanup OpenSSL resources
void cleanup_openssl() {
    EVP_cleanup();
}

// Load certificates for DTLS
void load_certificates(SSL_CTX *ctx, bool is_server) {
    const char* certificate;
    if(is_server) {
        certificate = "bob.crt";
    } else {
        certificate = "alice.crt";
    }

    if (!SSL_CTX_use_certificate_file(ctx, certificate, SSL_FILETYPE_PEM)) {
        perror("cert");
        exit(EXIT_FAILURE);
    }
}

// Load private key for DTLS
void load_private_key(SSL_CTX *ctx, bool is_server) {
    const char* private_key;
    if(is_server) {
        private_key = "bob-private-key.pem";
    } else {
        private_key = "alice-private-key.pem";
    }
    if (!SSL_CTX_use_PrivateKey_file(ctx, private_key, SSL_FILETYPE_PEM)) {
        perror("key");
        exit(EXIT_FAILURE);
    }
}

// Load CA certificate for DTLS
void load_CAcert(SSL_CTX *ctx) {
    if(!SSL_CTX_load_verify_locations(ctx,"CAcert.pem",NULL)) {
        perror("chain");
        exit(EXIT_FAILURE);
    }
}

// Configure DTLS context
void configure_ctx(SSL_CTX *ctx) {
    SSL_CTX_set_security_level(ctx, 1);
    SSL_CTX_set_mode(ctx, SSL_MODE_AUTO_RETRY);
    SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
}

// Send messages over DTLS connection
void send_messages(SSL *ssl, const char* message) {
    if(SSL_write(ssl, message, strlen(message)) != strlen(message)) {
        error_handler("SSL_write failed");
    }
}

// Receive messages over DTLS connection
void receiver_message(SSL* ssl, char (&buffer)[MAX_SIZE]) {
    int recvd_msg_size = SSL_read(ssl, buffer, MAX_SIZE - 1);
    if (recvd_msg_size < 0) {
        error_handler("SSL_read failed");
    }
    buffer[recvd_msg_size] = '\0';
}

// Client function
void client(const char* hostname) {
    int sockfd;
    char buffer[MAX_SIZE];
    bool is_server = false;
    SSL *ssl;
    bool ssl_check = false;

    // Create a socket
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        error_handler("Failed to create socket");
    }

    // Get server address
    struct sockaddr_in server_addr;
    struct hostent* server = gethostbyname(hostname);

    // Check if server address is valid
    if(server == nullptr) {
        error_handler("Failed to get server address");
    }

    // Set server address and port
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);
    memcpy(&server_addr.sin_addr.s_addr, server->h_addr, server->h_length);
    socklen_t addr_len;
    struct timeval timeout_handshake;

     while(true){
        // Send initial message to server
        sendto(sockfd, "chat_hello", strlen("chat_hello"), 0, (struct sockaddr*)&server_addr, sizeof(server_addr));

        // Set receive timeout for socket
        timeout_handshake.tv_sec = 2; // 2 seconds timeout
        timeout_handshake.tv_usec = 0;
        if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout_handshake, sizeof(timeout_handshake)) < 0) {
            error_handler("Error setting socket receive timeout");
        }

        // Receive response from server
        int recvd_msg_size = recvfrom(sockfd, buffer, MAX_SIZE - 1, 0, (struct sockaddr*)&server_addr, &addr_len);
        if (recvd_msg_size < 0) {
            if(errno == EWOULDBLOCK) {
                cout << "Timeout occurred: No message received within 2 seconds" << endl;
                continue;
            }else{
                cout << "Failed response from server" << endl;
                continue;
            }
        }
        buffer[recvd_msg_size] = '\0';
        cout << "Server: " << buffer << endl;

        // If server acknowledges, initiate DTLS handshake
        if(strcmp(buffer, "chat_ok_reply") == 0) {
            break;
        }
    }

    while(true){
        sendto(sockfd, "chat_START_SSL", strlen("chat_START_SSL"), 0, (struct sockaddr*)&server_addr, addr_len);

        // Set receive timeout for socket
        timeout_handshake.tv_sec = 2; // 2 seconds timeout
        timeout_handshake.tv_usec = 0;
        if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout_handshake, sizeof(timeout_handshake)) < 0) {
            error_handler("Error setting socket receive timeout");
        }

        // Receive response for DTLS initiation
        int recvd_msg_size = recvfrom(sockfd, buffer, MAX_SIZE - 1, 0, (struct sockaddr*)&server_addr, &addr_len);
        if (recvd_msg_size < 0) {
            if(errno == EWOULDBLOCK) {
                cout << "Timeout occurred: No message received within 2 seconds" << endl;
                continue;
            }else{
                cout << "Failed response from server" << endl;
                continue;
            }
        }
        buffer[recvd_msg_size] = '\0';
        cout << "Server: " << buffer << endl;

        if(strcmp(buffer, "chat_START_SSL_ACK") == 0){
            ssl_check = true;
            break;
        }else if(strcmp(buffer, "chat_START_SSL_NOT_SUPPORTED") == 0){
            break;
        }
    }

    timeout_handshake.tv_sec = 0; 
    timeout_handshake.tv_usec = 0;
    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout_handshake, sizeof(timeout_handshake)) < 0) {
        error_handler("Error setting socket receive timeout");
    }

    // If DTLS initiation acknowledged, establish connection
    if(ssl_check) {
        sleep(6);
        cout << "Slept for 6 seconds" << endl;
        if (connect(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
            error_handler("Failed to connect");
        }
        SSL_CTX *ctx = SSL_CTX_new(DTLSv1_2_client_method());
        configure_ctx(ctx);
        load_certificates(ctx, is_server);
        load_private_key(ctx, is_server);
        // Verify private key
        if(!SSL_CTX_check_private_key(ctx)) {
            error_handler("Private key verification failed");
        }
        load_CAcert(ctx);
        const char *pfs_ciphers = "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384";
        if (SSL_CTX_set_cipher_list(ctx, pfs_ciphers) != 1) {
            ERR_print_errors_fp(stderr);
            error_handler("Failed to set cipher suites");
        }

        ssl = SSL_new(ctx);
        SSL_set_fd(ssl, sockfd);

        if (setSocketNonBlocking(sockfd) == -1) {
            cerr << "Error setting socket to non-blocking mode" << endl;
            SSL_CTX_free(ctx);
            SSL_shutdown(ssl);
            SSL_free(ssl);
            error_handler("");
        }

        int res;
        do{
            res = SSL_connect(ssl);
            cout << ".";
        }while(res != 1);

        cout << "" << endl;    

        cout << "DTLS handshake successfull with server" << endl;

        if (setSocketBlocking(sockfd) == -1) {
            cerr << "Error setting socket to non-blocking mode" << endl;
            SSL_CTX_free(ctx);
            SSL_shutdown(ssl);
            SSL_free(ssl);
            error_handler("");
        }

        


        // Chat loop
        while(true) {
            cout << "Me: ";
            string inp;
            getline(cin, inp);
            const char* msg;
            msg = &inp[0];
            send_messages(ssl, msg);
            if(strcmp(msg, "chat_close") == 0) {
                cout << "exit" << endl;
                break;
            }

            receiver_message(ssl, buffer);
            if(strcmp(buffer, "chat_close") == 0) {
                cout << "exit" << endl;
                break;
            }

            cout << "Server: " << buffer << endl;
        }

        SSL_CTX_free(ctx);
        SSL_shutdown(ssl);
        SSL_free(ssl);
    }else if(!ssl_check){
        // Chat loop
        while(true) {
            cout << "Me: ";
            string inp;
            getline(cin, inp);
            const char* msg;
            msg = &inp[0];
            sendto(sockfd, msg, strlen(msg), 0, (struct sockaddr*)&server_addr, addr_len);
            if(strcmp(msg, "chat_close") == 0) {
                cout << "exit" << endl;
                break;
            }

            int recvd_msg_size = recvfrom(sockfd, buffer, MAX_SIZE - 1, 0, (struct sockaddr*)&server_addr, &addr_len);
            if (recvd_msg_size < 0) {
                error_handler("Failed response from server");
            }
            buffer[recvd_msg_size] = '\0';
            cout << "Server: " << buffer << endl;
            if(strcmp(buffer, "chat_close") == 0) {
                cout << "exit" << endl;
                break;
            }

        }
    }

    close(sockfd);
}

// Server function
void server() {
    int sockfd;
    char buffer[MAX_SIZE];
    bool is_server = true;
    SSL *ssl;
    BIO *bio;
    struct timeval timeout;
    bool ssl_check = false;
    bool all_cm = false;

    // Create a socket
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        error_handler("Failed to create socket");
    }

    // Set server address and bind the socket
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    server_addr.sin_port = htons(SERVER_PORT);

    if (bind(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        error_handler("Failed to bind server socket");
    }

    struct sockaddr_in client_addr;
    socklen_t addr_len = sizeof(client_addr);

    cout << "Server is now listening......." << endl;

    // Set receive timeout for socket
    struct timeval timeout_handshake;

    // Wait for client's initial message
    while(true) {
        int recvd_msg_size;
        if(all_cm){
            timeout_handshake.tv_sec = 5; // 5 seconds timeout
            timeout_handshake.tv_usec = 0;
            if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout_handshake, sizeof(timeout_handshake)) < 0) {
                error_handler("Error setting socket receive timeout");
            }

            // Receive response for DTLS initiation
            recvd_msg_size = recvfrom(sockfd, buffer, MAX_SIZE - 1, 0, (struct sockaddr*)&client_addr, &addr_len);
            if (recvd_msg_size < 0) {
                if(errno == EWOULDBLOCK) {
                    cout << "Timeout occurred: No message received within 5 seconds" << endl;
                    break;
                }
            }
        }else{
            recvd_msg_size = recvfrom(sockfd, buffer, MAX_SIZE - 1, 0, (struct sockaddr*)&client_addr, &addr_len);
        }
        if (recvd_msg_size < 0) {
            error_handler("Failed handshake from client");
        }
        buffer[recvd_msg_size] = '\0';
        cout << "Client: " << buffer << endl;
        if(strcmp(buffer, "chat_hello") == 0) {
            sendto(sockfd, "chat_ok_reply", strlen("chat_ok_reply"), 0, (struct sockaddr*)&client_addr, addr_len);
        } else if(strcmp(buffer, "chat_START_SSL") == 0) {
            sendto(sockfd, "chat_START_SSL_ACK", strlen("chat_START_SSL_ACK"), 0, (struct sockaddr*)&client_addr, addr_len);
            ssl_check = true;
            all_cm = true;
            continue;
        }else{
            break;
        }
    }
    

    
    if(ssl_check){
        // Initialize DTLS context for server
        SSL_CTX *ctx = SSL_CTX_new(DTLSv1_2_server_method());
        configure_ctx(ctx);
        SSL_CTX_set_cookie_generate_cb(ctx,generate_cookie);
        SSL_CTX_set_cookie_verify_cb(ctx,&verify_cookie);
        load_certificates(ctx, is_server);
        load_private_key(ctx, is_server);
        // Verify private key
        if(!SSL_CTX_check_private_key(ctx)) {
            error_handler("Private key verification failed");
        }
        load_CAcert(ctx);

        // Set receive timeout for BIO
        timeout.tv_sec = 5;
        timeout.tv_usec = 0;
        bio = BIO_new_dgram(sockfd, BIO_NOCLOSE);
        BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &timeout);
        if(!bio) {
            error_handler("bio failed to setup");
        }

        // Create SSL object and set options
        ssl = SSL_new(ctx);
        SSL_set_options(ssl,SSL_OP_COOKIE_EXCHANGE);
        SSL_set_bio(ssl, bio, bio);

        if (setSocketNonBlocking(sockfd) == -1) {
            cerr << "Error setting socket to non-blocking mode" << endl;
            SSL_CTX_free(ctx);
            SSL_shutdown(ssl);
            SSL_free(ssl);
            error_handler("");
        }
            
        int res = 0;
        // Listen for incoming connections
        do{
            res = DTLSv1_listen(ssl, (BIO_ADDR *) &client_addr);
        }while(res < 0);

        // Accept DTLS connection
        do{
            res = SSL_accept(ssl);
        }while(res < 0);

        cout << "DTLS handshake successfull with client" << endl;

        if (setSocketBlocking(sockfd) == -1) {
            cerr << "Error setting socket to non-blocking mode" << endl;
            SSL_CTX_free(ctx);
            SSL_shutdown(ssl);
            SSL_free(ssl);
            error_handler("");
        }

        // Verify client's certificate
        if(SSL_get_peer_certificate(ssl)) {
            if( SSL_get_verify_result(ssl) == X509_V_OK) {
                cout << "Client Certificate Verified! \n";
            }
        } else {
            error_handler("Failed to get peer certificate");
        }
            
        timeout.tv_sec = 0;
        timeout.tv_usec = 0;
        BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &timeout);


        // Chat loop
        while(true) {
            receiver_message(ssl, buffer);
            if(strcmp(buffer, "chat_close") == 0) {
                cout << "exit" << endl;
                break;
            }
            cout << "client: " << buffer << endl;            

            cout << "Me: ";
            string inp;
            getline(cin, inp);
            const char* msg;
            msg = &inp[0];
            send_messages(ssl, msg);
            if(strcmp(msg, "chat_close") == 0) {
                cout << "exit" << endl;
                break;
            }
        }

        // Cleanup
        SSL_CTX_free(ctx);
        SSL_shutdown(ssl);
        SSL_free(ssl);
    }else if(!ssl_check){
        while(true) {
            if(strcmp(buffer, "chat_close") == 0) {
                cout << "exit" << endl;
                break;
            }

            cout << "Me: ";
            string inp;
            getline(cin, inp);
            const char* msg;
            msg = &inp[0];
            sendto(sockfd, msg, strlen(msg), 0, (struct sockaddr*)&client_addr, addr_len);
            if(strcmp(msg, "chat_close") == 0) {
                cout << "exit" << endl;
                break;
            }

            int recvd_msg_size = recvfrom(sockfd, buffer, MAX_SIZE - 1, 0, (struct sockaddr*)&client_addr, &addr_len);
            if (recvd_msg_size < 0) {
                error_handler("Failed message from client");
            }
            buffer[recvd_msg_size] = '\0';
            cout << "Client: " << buffer << endl;            

        }
    }
    close(sockfd);
}
  
// Main function
int main(int argc, char* argv[]) {
    cout << "You have entered " << argc << " arguments:" << endl; 
    initialize_openssl();
  
    // Check command line arguments
    if (argc < 2 || argc > 3) {
        cerr << "Usage: " << argv[0] << " -s (for server) or "<< argv[0] << " -c <server_hostname> (for client)" << std::endl;
        exit(EXIT_FAILURE);
    }

    // Run client or server based on arguments
    if (argc == 3 && strcmp(argv[1], "-c") == 0) {
        client(argv[2]);
    } else if (argc == 2 && strcmp(argv[1], "-s") == 0) {
        server();
    } else {
        cerr << "INVALID ARGUMENTS" << endl;
        cerr << "Usage: " << argv[0] << " -s (for server) or "<< argv[0] << " -c <server_hostname> (for client)" << std::endl;
        exit(EXIT_FAILURE);
    }
}
  