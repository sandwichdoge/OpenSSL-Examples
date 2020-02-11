#ifndef CRYPT_H_
#define CRYPT_H_
enum ALG_ID {ALG_AES_128 = 0, ALG_AES_256};

/* Encrypt raw data
    * Return value: Len of raw encrypted data
    * */ 
static int crypt_encrypt_data(char* data, int data_len, const char* cryptKey, enum ALG_ID algorithm, char* raw_out);

/* Decrypt data
* Return value: Len of decrypted data
* */
static int crypt_decrypt_data(char* data, int data_len, const char* cryptKey, enum ALG_ID algorithm, char* raw_out);

#endif