#include "smtp.h"

size_t smtp_read_line(SSL* ssl, char* out_buff, size_t buffer_len)
{
    size_t index = 0;
    for(;index<buffer_len;index++) {
        // read char
        // put it on the out_buff
        // if out_buff endswith \r\n break
        char current;
        int ret = SSL_read(ssl, &current, 1);
        if(ret!=1) {
            printf("ERROR: cannot complete SSL_read. ret code: %d\n", ret);
            return -1;
            // TODO: check return value, maybe we just need to read again or something
            // doc link: https://docs.openssl.org/master/man3/SSL_get_error/
        }
        out_buff[index] = current;
        if(out_buff && out_buff[index]=='\n' && out_buff[index-1]=='\r') break;
    }
    index++;
    if(index<buffer_len) out_buff[index] = '\0';
    return index;
}

bool smtp_its_last_line(char* line_string) {
    if(!line_string || strlen(line_string)<4) return false;
    return line_string[3]==0x20?true:false;
}

int smtp_read_response(SSL* ssl, char* out_buff, size_t buffer_len)
{
    char* line_buffer = malloc(1024);
    if(line_buffer==NULL) {
        perror("ERROR: malloc");
        return -1;
    }

    size_t out_buffer_i = 0;
    while (out_buffer_i<buffer_len)
    {
        // read line
        // copy line to the output
        // check if its the last one
        // if so, break
        size_t line_len = smtp_read_line(ssl, line_buffer, 1024);
        if(line_len==-1) {
            printf("ERROR: smtp_read_line\n");
            return -1;
        }
        memcpy(out_buff+out_buffer_i, line_buffer, line_len);
        if(smtp_its_last_line(line_buffer)) break;
        out_buffer_i += line_len;
    }
    free(line_buffer);
    return 0;
}
