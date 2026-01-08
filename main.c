#include <stdio.h>
#include <stdio.h>
#include <readline/readline.h>
#include <readline/history.h>
#include <errno.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <fcntl.h>

#include <openssl/ssl.h>
#include "smtp.h"

#define CRLF "\r\n"

#define FROM_APPNAME "smtp_test_app"
#define FROM "yosefshalomtz@gmail.com"
#define FROM_NAME "Yosef Shalom Tzuberi"
#define TO FROM
#define MAIL_SUBJECT "Test"
#define MAIL_DATE "Tue, 8 Jan 2026 17:29:00 +0000"
#define MAIL_BODY "Test :)"

#define AUTH_BASE64_USER "eW9zZWZzaGFsb210eg==" CRLF
#define AUTH_BASE64_PASS "aHRpdyBieWx1IHhrd2ogb3BpZA==" CRLF // not working

#define RHOST "74.125.128.109" // smtp.google.com
#define RHOST_DNS_NAME "smtp.google.com"
#define RPORT 465

int main()
{
    int ret;
    const SSL_METHOD *ssl_m = TLS_client_method();
    SSL_CTX *ctx = SSL_CTX_new(ssl_m);
    if (!ctx)
    {
        printf("ERROR: Failed to create SSL_CTX\n");
        return -1;
    }
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

    SSL *ssl = SSL_new(ctx);
    if (!ssl)
    {
        printf("ERROR: SSL_new failed\n");
        return -1;
    }

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0)
    {
        perror("ERROR: socket");
        return -1;
    }

    struct sockaddr_in sa = {0};
    sa.sin_family = AF_INET;
    sa.sin_port = htons(RPORT);
    ret = inet_pton(AF_INET, RHOST, &sa.sin_addr.s_addr);
    if (ret != 1)
    {
        perror("ERROR: inet_pton");
        return -1;
    }
    printf("DEBUG: ip %08X\n", sa.sin_addr.s_addr);

    ret = connect(sock, (struct sockaddr *)&sa, sizeof(sa));
    if (ret < 0)
    {
        perror("ERROR: connect");
        return -1;
    }
    printf("DEBUG: connected!\n");

    BIO *bio = BIO_new(BIO_s_socket());
    if (!bio)
    {
        printf("ERROR: BIO_new failed\n");
        BIO_closesocket(sock);
        return -1;
    }
    BIO_set_fd(bio, sock, BIO_CLOSE);

    SSL_set_bio(ssl, bio, bio);

    /*
     * Tell the server during the handshake which hostname we are attempting
     * to connect to in case the server supports multiple hosts.
     */
    if (!SSL_set_tlsext_host_name(ssl, RHOST_DNS_NAME))
    {
        printf("ERROR: Failed to set the SNI hostname\n");
        return -1;
    }
    /*
     * Ensure we check during certificate verification that the server has
     * supplied a certificate for the hostname that we were expecting.
     * Virtually all clients should do this unless you really know what you
     * are doing.
     */
    if (!SSL_set1_host(ssl, RHOST_DNS_NAME))
    {
        printf("ERROR: Failed to set the certificate verification hostname");
        return -1;
    }
    /**
     * load the default CAs file
     */
    if (!SSL_CTX_set_default_verify_paths(ctx))
    {
        printf("ERROR: Failed to load system CA certificates\n");
        return -1;
    }
    printf("DEBUG: system CA certificates loaded seccussfully.\n");

    /* Do the handshake with the server */
    if (SSL_connect(ssl) < 1)
    {
        printf("ERROR: Failed to connect to the server\n");
        /*
         * If the failure is due to a verification error we can get more
         * information about it from SSL_get_verify_result().
         */
        long err_code = SSL_get_verify_result(ssl);
        if (err_code != X509_V_OK)
            printf("ERROR: Verify error: %s\n", X509_verify_cert_error_string(err_code));
        return -1;
    }

    char *response_buff = malloc(1024);
    const char *client_hello = "EHLO " FROM_APPNAME CRLF;
    const char *auth_req = "AUTH LOGIN" CRLF;
    const char *mail_from = "MAIL FROM:<" FROM ">" CRLF;
    const char *rcpt_to = "RCPT TO:<" TO ">" CRLF;
    const char *data_req = "DATA" CRLF;

    const char *mail_body =
        "From: " FROM_NAME " <" FROM ">" CRLF
        "To: " TO CRLF
        "Subject: " MAIL_SUBJECT CRLF
        "Date: " MAIL_DATE CRLF
        "MIME-Version: 1.0" CRLF
        "Content-Type: text/plain; charset=UTF-8" CRLF CRLF
            MAIL_BODY CRLF
        "." CRLF;

    smtp_read_response(ssl, response_buff, 1024);
    printf("INFO: server hello\n%s\n", response_buff);

    SSL_write(ssl, client_hello, strlen(client_hello));
    smtp_read_response(ssl, response_buff, 1024);
    printf("INFO: server cap's\n%s\n", response_buff);

    SSL_write(ssl, auth_req, strlen(auth_req));
    smtp_read_response(ssl, response_buff, 1024);
    printf("INFO: authentication request sent...\n%s\n", response_buff);

    SSL_write(ssl, AUTH_BASE64_USER, strlen(AUTH_BASE64_USER));
    smtp_read_response(ssl, response_buff, 1024);
    printf("INFO: AUTH_BASE64_USER sent...\n%s\n", response_buff);

    SSL_write(ssl, AUTH_BASE64_PASS, strlen(AUTH_BASE64_PASS));
    smtp_read_response(ssl, response_buff, 1024);
    printf("INFO: AUTH_BASE64_PASS sent...\n%s\n", response_buff);

    SSL_write(ssl, mail_from, strlen(mail_from));
    smtp_read_response(ssl, response_buff, 1024);
    printf("INFO: MAIL FROM request sent...\n%s\n", response_buff);

    SSL_write(ssl, rcpt_to, strlen(rcpt_to));
    smtp_read_response(ssl, response_buff, 1024);
    printf("INFO: RCPT TO request sent...\n%s\n", response_buff);

    SSL_write(ssl, data_req, strlen(data_req));
    smtp_read_response(ssl, response_buff, 1024);
    printf("INFO: DATA sent...\n%s\n", response_buff);

    SSL_write(ssl, mail_body, strlen(mail_body));
    smtp_read_response(ssl, response_buff, 1024);
    printf("INFO: mail body sent...\n%s\n", response_buff);

    ret = SSL_shutdown(ssl);
    if (ret < 0)
    {
        /*
         * ret < 0 indicates an error. ret == 0 would be unexpected here
         * because that means "we've sent a close_notify and we're waiting
         * for one back". But we already know we got one from the peer
         * because of the SSL_ERROR_ZERO_RETURN above.
         */
        printf("ERROR: Error shutting down. ret code: %d\n", ret);
        return -1;
    }

    printf("INFO: Done!\n");

    free(response_buff);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    return 0;
}