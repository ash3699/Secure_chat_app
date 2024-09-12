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

// Initialize OpenSSL
void initialize_openssl() {
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
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
        certificate = "bob-fake.crt";
    } else {
        certificate = "alice-fake.crt";
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
        private_key = "bob-fake-private-key.pem";
    } else {
        private_key = "alice-fake-private-key.pem";
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


void passive_interceptor(const char* hostname, const char* servername) { 
    int sockfd_client, sockfd_server;
    char buffer[MAX_SIZE];

    // Create a socket
    if ((sockfd_client = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        error_handler("Failed to create socket");
    }

    // Set server address and bind the socket
    struct sockaddr_in trudy_addr;
    memset(&trudy_addr, 0, sizeof(trudy_addr));
    trudy_addr.sin_family = AF_INET;
    trudy_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    trudy_addr.sin_port = htons(SERVER_PORT);

    if (bind(sockfd_client, (struct sockaddr*)&trudy_addr, sizeof(trudy_addr)) < 0) {
        error_handler("Failed to bind server socket");
    }

    struct sockaddr_in client_addr;
    socklen_t addr_len_c = sizeof(client_addr);

    if ((sockfd_server = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        error_handler("Failed to create socket");
    }

    // Get server address
    struct sockaddr_in server_addr;
    struct hostent* server = gethostbyname(servername);
    socklen_t addr_len_s = sizeof(server_addr);


    // Set server address and port
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);
    memcpy(&server_addr.sin_addr.s_addr, server->h_addr, server->h_length);
    //server_addr.sin_addr.s_addr = inet_addr("10.8.9.16");


    while(true) {
        int recvd_msg_size = recvfrom(sockfd_client, buffer, MAX_SIZE - 1, 0, (struct sockaddr*)&client_addr, &addr_len_c);
        if (recvd_msg_size < 0) {
            error_handler("Failed handshake from client");
        }
        buffer[recvd_msg_size] = '\0';
        cout << "Client: " << buffer << endl;
        if(strcmp(buffer, "chat_START_SSL") == 0) {
            sendto(sockfd_client, "chat_START_SSL_NOT_SUPPORTED", strlen("chat_START_SSL_NOT_SUPPORTED"), 0, (struct sockaddr*)&client_addr, sizeof(client_addr));
            continue;
        }else{
            sendto(sockfd_server, buffer, strlen(buffer), 0, (struct sockaddr*)&server_addr, sizeof(server_addr));
        }

        recvd_msg_size = recvfrom(sockfd_server, buffer, MAX_SIZE - 1, 0, (struct sockaddr*)&server_addr, &addr_len_s);
        if (recvd_msg_size < 0) {
            error_handler("Failed response from server");
        }
        buffer[recvd_msg_size] = '\0';
        cout << "Server: " << buffer << endl;

        sendto(sockfd_client, buffer, strlen(buffer), 0, (struct sockaddr*)&client_addr, sizeof(client_addr));

    }

    close(sockfd_client);
    close(sockfd_server);
    return ;
}

// Server function
void active_interceptor(const char* hostname, const char* servername) { 
    initialize_openssl();
    int sockfd_client, sockfd_server;
    char buffer[MAX_SIZE];
    bool is_server = true;
    SSL *ssl_client;
    SSL *ssl_server;
    BIO *bio;
    struct timeval timeout;
    bool ssl_check = false;

    // Create a socket
    if ((sockfd_client = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        error_handler("Failed to create socket");
    }

    // Set server address and bind the socket
    struct sockaddr_in trudy_addr;
    memset(&trudy_addr, 0, sizeof(trudy_addr));
    trudy_addr.sin_family = AF_INET;
    trudy_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    trudy_addr.sin_port = htons(SERVER_PORT);

    if (bind(sockfd_client, (struct sockaddr*)&trudy_addr, sizeof(trudy_addr)) < 0) {
        error_handler("Failed to bind server socket");
    }

    struct sockaddr_in client_addr;
    socklen_t addr_len_c = sizeof(client_addr);

    if ((sockfd_server = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        error_handler("Failed to create socket");
    }

    // Get server address
    struct sockaddr_in server_addr;
    struct hostent* server = gethostbyname(servername);
    socklen_t addr_len_s = sizeof(server_addr);


    // Set server address and port
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);
    memcpy(&server_addr.sin_addr.s_addr, server->h_addr, server->h_length);
    //server_addr.sin_addr.s_addr = inet_addr("10.8.9.16");


    while(true) {
        int recvd_msg_size = recvfrom(sockfd_client, buffer, MAX_SIZE - 1, 0, (struct sockaddr*)&client_addr, &addr_len_c);
        if (recvd_msg_size < 0) {
            error_handler("Failed handshake from client");
        }
        buffer[recvd_msg_size] = '\0';
        cout << "Alice: " << buffer << endl;
        
        
        
        sendto(sockfd_server, buffer, strlen(buffer), 0, (struct sockaddr*)&server_addr, sizeof(server_addr));
        

        recvd_msg_size = recvfrom(sockfd_server, buffer, MAX_SIZE - 1, 0, (struct sockaddr*)&server_addr, &addr_len_s);
        if (recvd_msg_size < 0) {
            error_handler("Failed response from server");
        }
        buffer[recvd_msg_size] = '\0';
        cout << "Server: " << buffer << endl;

        sendto(sockfd_client, buffer, strlen(buffer), 0, (struct sockaddr*)&client_addr, sizeof(client_addr));
        if(strcmp(buffer, "chat_START_SSL_ACK") == 0) {
            break;
        }

    }

    ssl_check=true;
    
    if(ssl_check){
        // Initialize DTLS context when trudy acts as server
        SSL_CTX *ctx_client = SSL_CTX_new(DTLSv1_2_server_method());
        configure_ctx(ctx_client);
        SSL_CTX_set_cookie_generate_cb(ctx_client,generate_cookie);
        SSL_CTX_set_cookie_verify_cb(ctx_client,&verify_cookie);
        load_certificates(ctx_client, is_server);
        load_private_key(ctx_client, is_server);
        // Verify private key
        if(!SSL_CTX_check_private_key(ctx_client)) {
            error_handler("Private key verification failed");
        }
        load_CAcert(ctx_client);
	
        timeout.tv_sec = 5;
        timeout.tv_usec = 0;
        bio = BIO_new_dgram(sockfd_client, BIO_NOCLOSE);
        BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &timeout);
        if(!bio) {
            error_handler("bio failed to setup");
        }
	    // Create SSL object and set options
        ssl_client = SSL_new(ctx_client);
        SSL_set_options(ssl_client,SSL_OP_COOKIE_EXCHANGE);
        SSL_set_bio(ssl_client, bio, bio);
	    int res = 0;
        // Listen for incoming connections

        if (setSocketNonBlocking(sockfd_client) == -1) {
            cerr << "Error setting socket to non-blocking mode" << endl;
            SSL_CTX_free(ctx_client);
            SSL_shutdown(ssl_client);
            SSL_free(ssl_client);
            error_handler("");
        }
            
        
        // Listen for incoming connections
        do{
            res = DTLSv1_listen(ssl_client, (BIO_ADDR *) &client_addr);
        }while(res < 0);

        // Accept DTLS connection
        do{
            res = SSL_accept(ssl_client);
        }while(res < 0);

        cout << "DTLS handshake successfull with client" << endl;

        if (setSocketBlocking(sockfd_client) == -1) {
            cerr << "Error setting socket to non-blocking mode" << endl;
            SSL_CTX_free(ctx_client);
            SSL_shutdown(ssl_client);
            SSL_free(ssl_client);
            error_handler("");
        }

        // Verify client's certificate
        if(SSL_get_peer_certificate(ssl_client)) {
            if( SSL_get_verify_result(ssl_client) == X509_V_OK) {
                cout << "Client Certificate Verified! \n";
            }
        } else {
            error_handler("Failed to get peer certificate");
        }
            
        timeout.tv_sec = 0;
        timeout.tv_usec = 0;
        BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &timeout);


        if (connect(sockfd_server, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
            error_handler("Failed to connect");
        }

        // Initialize DTLS context when trudy acts as client 
        SSL_CTX *ctx_server = SSL_CTX_new(DTLSv1_2_client_method());
        configure_ctx(ctx_server);
        load_certificates(ctx_server, !is_server);
        load_private_key(ctx_server, !is_server);
        // Verify private key
        if(!SSL_CTX_check_private_key(ctx_server)) {
            error_handler("Private key verification failed");
        }
        load_CAcert(ctx_server);
        const char *pfs_ciphers = "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384";
        if (SSL_CTX_set_cipher_list(ctx_server, pfs_ciphers) != 1) {
            ERR_print_errors_fp(stderr);
            error_handler("Failed to set cipher suites");
        }

        ssl_server = SSL_new(ctx_server);
        SSL_set_fd(ssl_server, sockfd_server);

        if (setSocketNonBlocking(sockfd_server) == -1) {
            cerr << "Error setting socket to non-blocking mode" << endl;
            SSL_CTX_free(ctx_server);
            SSL_shutdown(ssl_server);
            SSL_free(ssl_server);
            error_handler("");
        }

        do{
            res = SSL_connect(ssl_server);
        }while(res != 1);

    

        cout << "DTLS handshake successfull with server" << endl;

        if (setSocketBlocking(sockfd_server) == -1) {
            cerr << "Error setting socket to non-blocking mode" << endl;
            SSL_CTX_free(ctx_server);
            SSL_shutdown(ssl_server);
            SSL_free(ssl_server);
            error_handler("");
        }

        
	    cout << "SSL done!" << endl;

        bool client_closed = false;
        bool server_closed = false;

        // Chat loop
        while(true) {
            
            if(!client_closed){
                receiver_message(ssl_client, buffer);
                cout << "Alice: " << buffer << endl;
                // string inp;
                // getline(cin, inp);
                const char* msg_server;
                msg_server = &buffer[0];
                
                if(!server_closed){
                    cout << "Enter 'c' if you want to end chat with server" << endl;
                    cout << "Enter 'm' if you want to modify the msg to server" << endl;
                    string inp;
                    getline(cin, inp);

                    if ( inp == "c"){
                        send_messages(ssl_server, "chat_close");
                        cout << "ending chat with server" << endl;
                        server_closed = true;
                    }else if( inp == "m"){
                        cout << "To server: ";
                        string inp;
                        getline(cin, inp);
                        const char* msg;
                        msg = &inp[0];
                        send_messages(ssl_server, msg);
                    }else{
                        send_messages(ssl_server, msg_server);
                        if(strcmp(msg_server, "chat_close") == 0) {
                            cout << "exit" << endl;
                            break;
                        }
                    }

                }
            }else{
                cout << "To server: ";
                string inp;
                getline(cin, inp);
                const char* msg;
                msg = &inp[0];
                send_messages(ssl_server, msg);
                if(strcmp(msg, "chat_close") == 0) {
                    cout << "exit" << endl;
                    break;
                }
            }

            if(!server_closed){
                receiver_message(ssl_server, buffer);

                cout << "Bob: " << buffer << endl;
                // string inp;
                // getline(cin, inp);
                const char* msg_client;
                msg_client = &buffer[0];

                if(!client_closed){
                    cout << "Enter 'c' if you want to end chat with client" << endl;
                    cout << "Enter 'm' if you want to modify the msg to client" << endl;
                    string inp;
                    getline(cin, inp);

                    if ( inp == "c"){
                        send_messages(ssl_client, "chat_close");
                        cout << "ending chat with client" << endl;
                        client_closed = true;
                    }else if( inp == "m"){
                        cout << "To client: ";
                        string inp;
                        getline(cin, inp);
                        const char* msg;
                        msg = &inp[0];
                        send_messages(ssl_client, msg);
                    }else{
                        send_messages(ssl_client, msg_client);
                        if(strcmp(msg_client, "chat_close") == 0) {
                            cout << "exit" << endl;
                            break;
                        }
                    }
                }
            }else{
                cout << "To client: ";
                string inp;
                getline(cin, inp);
                const char* msg;
                msg = &inp[0];
                send_messages(ssl_client, msg);
                if(strcmp(msg, "chat_close") == 0) {
                    cout << "exit" << endl;
                    break;
                }
            }
            

        }
        

        // Cleanup
        SSL_CTX_free(ctx_client);
        SSL_shutdown(ssl_client);
        SSL_CTX_free(ctx_server);
        SSL_shutdown(ssl_server);
        SSL_free(ssl_server);
        SSL_free(ssl_client);
    
    }
    close(sockfd_client);
    close(sockfd_server);
}
  
// Main function
int main(int argc, char* argv[]) {
    cout << "You have entered " << argc << " arguments:" << endl;
  
    // Check command line arguments
    if (argc !=4) {
        cerr << "Usage: " << argv[0] << " -m <client_hostname> <server_hostname> (for active_interceptor) or "<< argv[0] << " -d <client_hostname> <server_hostname> (for passive_interceptor)" << std::endl;
        exit(EXIT_FAILURE);
    }

    // Run client or server based on arguments
    if (strcmp(argv[1], "-d") == 0) {
        passive_interceptor(argv[2], argv[3]);
    } else if (strcmp(argv[1], "-m") == 0) {
        active_interceptor(argv[2], argv[3]);
    } else {
        cerr << "INVALID ARGUMENTS" << endl;
        cerr << "Usage: " << argv[0] << " -m <client_hostname> <server_hostname> (for active_interceptor) or "<< argv[0] << " -d <client_hostname> <server_hostname> (for passive_interceptor)" << std::endl;
        exit(EXIT_FAILURE);
    }
  
    return 0;
}
