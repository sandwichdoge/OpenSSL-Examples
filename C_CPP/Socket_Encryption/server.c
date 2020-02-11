#include <stdio.h>
#include <stdlib.h>
#include <unistd.h> //read()/SSL_write()
#include <sys/types.h> //socket stuff
#include <sys/socket.h> //socket stuff
#include <netinet/in.h> //INADDR_ANY
#include <pthread.h> //multi-connection
#include <string.h> //memset()
#include <fcntl.h>
#include <openssl/rsa.h>
#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

//gcc ssl-server.c -lcrypto -lpthread -lssl

/*How to create RSA keypair:
 * openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes
 */

/*Creating socket server in C:
 *socket() -> setsocketopt() -> bind() -> listen() -> accept()
 *then read/write into socket returned by accept()
 */
/*Implementing SSL server in C:
 *Initialize SSL - SSL_library_init(), load_error_strings(), OpenSSL_add_all_algorithms()
 *Create CTX: SSL_CTX_new(method()) -> SSL_CTX_set_options()
 *SSL_CTX_use_certificate_file(), SSL_CTX_use_PrivateKey_file() -> SSL_CTX_check_private_key() to validate
 *---And we're done with global initialization---
 *---Connection ahead, require a client fd returned from accept() syscall---
 *ssl_connection = SSL_new(), ssl_set_fd() to link client_fd with ssl_connection
 *ssl_accept() to wait for client to initiate handshake, non-block I/O client_fd to implement timeout otherwise it'll hang on bad requests
 */

struct server_socket {
    int fd;
    socklen_t len;
    struct sockaddr_in *handle;
};

void initialize_SSL();
void disconnect_SSL(SSL *);
void *conn_handler(void *);
struct server_socket create_server_socket(int port);
SSL *conn_SSL;
SSL_CTX *ssl_ctx;

int main()
{
    int port = 4443;
    int new_fd = 0;

    struct server_socket sock = create_server_socket(port);
    pthread_t pthread;

    initialize_SSL();
    ssl_ctx = SSL_CTX_new(TLS_server_method());
    if (!ssl_ctx) {
        printf("Error creating CTX\n");
    }
    SSL_CTX_set_options(ssl_ctx, SSL_OP_SINGLE_DH_USE);

    int use_cert = SSL_CTX_use_certificate_file(ssl_ctx, "/home/z/certificate.pem" , SSL_FILETYPE_PEM);
    int use_prv = SSL_CTX_use_PrivateKey_file(ssl_ctx, "/home/z/key.pem", SSL_FILETYPE_PEM);
    if (!SSL_CTX_check_private_key(ssl_ctx)) {
        fprintf(stderr,"Private key does not match the certificate public key.\n");
        exit(-5);
    }

    printf("Listening on port %d\n", port);
    while (1) {
        new_fd = accept(sock.fd, (struct sockaddr*)sock.handle, &sock.len);
        if (new_fd > 0) {
            pthread_create(&pthread, NULL, conn_handler, &new_fd); //create a thread for each new connection
        }
    }
    printf("Server stopped\n");
    
    return 0;
}


struct server_socket create_server_socket(int port)
{
    int err = 0;
    struct server_socket ret;
    struct sockaddr_in server;

    server.sin_family = AF_INET;
    server.sin_port = htons(port);
    server.sin_addr.s_addr = INADDR_ANY;

    socklen_t len = sizeof(server);

    int fd = socket(AF_INET, SOCK_STREAM, 0); //Inet TCP
    if (!fd) printf("error creating socket\n");
    int opt = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt)); //optional, prevents address already in use error
    err = bind(fd, (struct sockaddr*)&server, sizeof(server));
    if (err < 0) printf("error binding\n");
    err = listen(fd, 16); //max connections
    if (err < 0) printf("error listening\n");

    ret.fd = fd;
    ret.len = len;
    ret.handle = &server;
    return ret;
}


void *conn_handler(void *fd)
{
    char buf[2048] = "";
    char msg[64] = "Welcome to echo server 1!\nEnter 'exit' to disconnect.";
    int client_fd = *(int*)fd;
    printf("Client connected, fd: %d\n", client_fd);
    //fcntl(client_fd, F_SETFL, O_NONBLOCK);

    conn_SSL = SSL_new(ssl_ctx);;
    if (!conn_SSL) printf("Error creating SSL\n");
    SSL_set_fd(conn_SSL, client_fd);
    //Here is the SSL Accept portion.  Now all reads and writes must use SSL
    int err = SSL_get_error(conn_SSL, SSL_accept(conn_SSL));
    printf ("SSL connection using %s\n", SSL_get_cipher(conn_SSL));
    fflush(stdout);
    SSL_write(conn_SSL, msg, sizeof(msg)); //send welcome message

    while (1) {
        SSL_read(conn_SSL, buf, sizeof(buf));  //get message from client
        if (buf[0] != 0) {
            if (strcmp(buf, "exit") == 0) {
                strcpy(buf, "Disconnected.\n");
                SSL_write(conn_SSL, buf, sizeof(buf)); //send disconnect msg to client
                break; //break if "exit" message is received
            }
            printf("Echoing: %s\n", buf);
            fflush(stdout);
            SSL_write(conn_SSL, buf, sizeof(buf)); //echo it back to client
            memset(buf, 0, sizeof(buf));
        }
    }

    printf("Shutting down client: %d\n", client_fd);
    fflush(stdout);
    close(client_fd);
    disconnect_SSL(conn_SSL);
}

void initialize_SSL()
{
    SSL_load_error_strings();
    SSL_library_init();
    OpenSSL_add_ssl_algorithms();
}

void shutdown_SSL()
{
    ERR_free_strings();
    EVP_cleanup();
}

void disconnect_SSL(SSL *conn_SSL)
{
    SSL_shutdown(conn_SSL);
    SSL_free(conn_SSL);
}