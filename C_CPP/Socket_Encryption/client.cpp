
#include <stdio.h>
#include <memory.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>

#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>


#define CHK_NULL(x) if ((x)==NULL) exit (1)
#define CHK_ERR(err,s) if ((err)==-1) { perror(s); exit(1); }
#define CHK_SSL(err) if ((err)==-1) { ERR_print_errors_fp(stderr); exit(2); }

int main(void)
{
  int err;
  int sd;
  struct sockaddr_in sa;
  SSL_CTX* ctx;
  SSL*     ssl;
  X509*    server_cert;
  char*    str;
  char     buf [4096];

  OpenSSL_add_ssl_algorithms();
  SSL_load_error_strings();
  ctx = SSL_CTX_new (TLS_client_method());                        CHK_NULL(ctx);

  /* ----------------------------------------------- */
  /* Create a socket and connect to server using normal socket calls. */
  
  sd = socket (AF_INET, SOCK_STREAM, 0);       CHK_ERR(sd, "socket");
 
  memset(&sa, 0, sizeof(sa));
  sa.sin_family      = AF_INET;
  sa.sin_addr.s_addr = inet_addr ("127.0.0.1");   /* Server IP */
  sa.sin_port        = htons     (4443);          /* Server Port number */
  
  err = connect(sd, (struct sockaddr*) &sa,
		sizeof(sa));                   CHK_ERR(err, "connect");

  /* ----------------------------------------------- */
  /* Now we have TCP conncetion. Start SSL negotiation. */
  
  ssl = SSL_new (ctx);                         CHK_NULL(ssl);    
  SSL_set_fd (ssl, sd);
  err = SSL_connect (ssl);                     CHK_SSL(err);
    
  /* Following two steps are optional and not required for
     data exchange to be successful. */
  
  /* Get the cipher - opt */

  printf ("SSL connection using %s\n", SSL_get_cipher (ssl));
  
  /* Get server's certificate (note: beware of dynamic allocation) - opt */

  server_cert = SSL_get_peer_certificate (ssl);       CHK_NULL(server_cert);
  printf ("Server certificate:\n");
  
  str = X509_NAME_oneline (X509_get_subject_name (server_cert),0,0);
  CHK_NULL(str);
  printf ("\t subject: %s\n", str);
  OPENSSL_free (str);

  str = X509_NAME_oneline (X509_get_issuer_name  (server_cert),0,0);
  CHK_NULL(str);
  printf ("\t issuer: %s\n", str);
  OPENSSL_free (str);

  /* We could do all sorts of certificate verification stuff here before
     deallocating the certificate. */

  X509_free (server_cert);
  
  /* --------------------------------------------------- */
  /* DATA EXCHANGE - Send a message and receive a reply. */
  printf("Enter your message for echo:\n");
  int msg[64];
  SSL_read (ssl, buf, sizeof(buf) - 1); 
  
  while (1) {
    scanf("%s", msg);
    err = SSL_write (ssl, msg, sizeof(msg));  CHK_SSL(err);
    err = SSL_read (ssl, buf, sizeof(buf) - 1);                     CHK_SSL(err);
    buf[err] = '\0';
    printf ("Got %d chars:'%s'\n", err, buf);
  }
  SSL_shutdown (ssl);  /* send SSL/TLS close_notify */

  /* Clean up. */

  //close (sd);
  SSL_free (ssl);
  SSL_CTX_free (ctx);
  return 0;
}