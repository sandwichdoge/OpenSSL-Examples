#include <openssl/evp.h>
#include "crypt.h"


int crypt_encrypt_data(char* data, int data_len, const char* cryptKey, enum ALG_ID algorithm, char* raw_out) {
    static unsigned char *iv = (unsigned char *)"0123456789012345";
    
    EVP_CIPHER_CTX *ctx;

    int len;
    int ciphertext_len;

    /* Create and initialise the context */
    if (!(ctx = EVP_CIPHER_CTX_new())) {
        // Handle error
        return -1;
    }

    const EVP_CIPHER* algo;
    switch (algorithm) {
        case ALG_AES_128:
            algo = EVP_aes_128_cbc();
            break;
        case ALG_AES_256:
            algo = EVP_aes_256_cbc();
            break;
    }

    /*
    * Initialise the encryption operation. IMPORTANT - ensure you use a key
    * and IV size appropriate for your cipher
    * In this example we are using 256 bit AES (i.e. a 256 bit key). The
    * IV size for *most* modes is the same as the block size. For AES this
    * is 128 bits
    */
    if (1 != EVP_EncryptInit_ex(ctx, algo, NULL, (const unsigned char*)cryptKey, iv)) {
        EVP_CIPHER_CTX_free(ctx);
        return -2;
    }

    /*
    * Provide the message to be encrypted, and obtain the encrypted output.
    * EVP_EncryptUpdate can be called multiple times if necessary
    */
    if (1 != EVP_EncryptUpdate(ctx, (unsigned char *)raw_out, &len, (const unsigned char*)data, data_len)) {
        EVP_CIPHER_CTX_free(ctx);
        return -3;
    }
    ciphertext_len = len;

    /*
    * Finalise the encryption. Further ciphertext bytes may be written at
    * this stage.
    */
    if(1 != EVP_EncryptFinal_ex(ctx, (unsigned char *)raw_out + len, &len)) {
        EVP_CIPHER_CTX_free(ctx);
        return -4;
    }
    ciphertext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

int crypt_decrypt_data(char* data, int data_len, const char* cryptKey, enum ALG_ID algorithm, char* raw_out) {
    static unsigned char *iv = (unsigned char *)"0123456789012345";
    EVP_CIPHER_CTX *ctx;

    int len;
    int plaintext_len;

    /* Create and initialise the context */
    if (!(ctx = EVP_CIPHER_CTX_new())) {
        return -1;
    }

    const EVP_CIPHER* algo;
    switch (algorithm) {
        case ALG_AES_128:
            algo = EVP_aes_128_cbc();
            break;
        case ALG_AES_256:
            algo = EVP_aes_256_cbc();
            break;
    }
    /*
    * Initialise the decryption operation. IMPORTANT - ensure you use a key
    * and IV size appropriate for your cipher
    * In this example we are using 256 bit AES (i.e. a 256 bit key). The
    * IV size for *most* modes is the same as the block size. For AES this
    * is 128 bits
    */
    if (1 != EVP_DecryptInit_ex(ctx, algo, NULL, (unsigned char*)cryptKey, iv)) {
        EVP_CIPHER_CTX_free(ctx);
        return -2;
    }

    /*
    * Provide the message to be decrypted, and obtain the plaintext output.
    * EVP_DecryptUpdate can be called multiple times if necessary.
    */
    if (1 != EVP_DecryptUpdate(ctx, (unsigned char*)raw_out, &len, (unsigned char*)data, data_len)) {
        EVP_CIPHER_CTX_free(ctx);
        return -3;
    }
    plaintext_len = len;

    /*
    * Finalise the decryption. Further plaintext bytes may be written at
    * this stage.
    */
    if (1 != EVP_DecryptFinal_ex(ctx, (unsigned char*)raw_out + len, &len)) {
        EVP_CIPHER_CTX_free(ctx);
        return -4;
    }
    plaintext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}