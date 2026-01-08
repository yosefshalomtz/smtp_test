#pragma once
#include <openssl/ssl.h>
#include <errno.h>
#include <stdbool.h>

/**
 * @brief Read a single line from an SSL SMTP textual response. (to a Null-Terminated string, including the CRLF)
 *
 * @param ssl        Pointer to an initialized SSL connection.
 * @param out_buff   Output buffer where the line will be stored.
 * @param buffer_len Size of the output buffer in bytes.
 *
 * @return
 * On success, returns the length of the line read (including the CRLF, excluding the null terminator).
 * Returns -1 on error.
 */
size_t smtp_read_line(SSL* ssl, char* out_buff, size_t buffer_len);

bool smtp_its_last_line(char* line_string);

/**
 * @return
 * On success, returns 0.
 * Returns -1 on error.
 */
int smtp_read_response(SSL* ssl, char* out_buff, size_t buffer_len);