#include "crypt.h"
#include <stdio.h>
#include <string.h>

int main()
{
    char buf[256] = {0};
    int len = crypt_encrypt_data("Hello, World!", strlen("Hello, World!"), "123", ALG_AES_128, buf);

    char buf_decrypt[256] = {0};
    int len_decrypt = crypt_decrypt_data(buf, len, "123", ALG_AES_128, buf_decrypt);
    
    buf_decrypt[len_decrypt] = '\0';
    if (strcmp(buf_decrypt, "Hello, World!") == 0) {
        printf("Test success!\n");
    } else {
        printf("Test failed!\n");
    }

    return 0;
}