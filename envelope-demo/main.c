#include <stdlib.h>
#include <stdio.h>

#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>


void handleErrors(void) {
	fprintf(stderr, "ERROR: %s\n", ERR_error_string(ERR_get_error(), NULL));
	exit(1);
}


int envelope_seal(EVP_PKEY **pub_key, unsigned char *plaintext, int plaintext_len,
	unsigned char **encrypted_key, int *encrypted_key_len, unsigned char *iv,
	unsigned char *ciphertext)
{
	EVP_CIPHER_CTX *ctx;

	int ciphertext_len;

	int len;


	/* Create and initialise the context */
	if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

	/* Initialise the envelope seal operation. This operation generates
	 * a key for the provided cipher, and then encrypts that key a number
	 * of times (one for each public key provided in the pub_key array). In
	 * this example the array size is just one. This operation also
	 * generates an IV and places it in iv. */
	if(1 != EVP_SealInit(ctx, EVP_aes_256_cbc(), encrypted_key,
		encrypted_key_len, iv, pub_key, 1))
		handleErrors();

	/* Provide the message to be encrypted, and obtain the encrypted output.
	 * EVP_SealUpdate can be called multiple times if necessary
	 */
	if(1 != EVP_SealUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
		handleErrors();
	ciphertext_len = len;

	/* Finalise the encryption. Further ciphertext bytes may be written at
	 * this stage.
	 */
	if(1 != EVP_SealFinal(ctx, ciphertext + len, &len)) handleErrors();
	ciphertext_len += len;

	/* Clean up */
	EVP_CIPHER_CTX_free(ctx);

	return ciphertext_len;
}

int envelope_open(EVP_PKEY *priv_key, unsigned char *ciphertext, int ciphertext_len,
	unsigned char *encrypted_key, int encrypted_key_len, unsigned char *iv,
	unsigned char *plaintext)
{
	EVP_CIPHER_CTX *ctx;

	int len;

	int plaintext_len;


	/* Create and initialise the context */
	if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

	/* Initialise the decryption operation. The asymmetric private key is
	 * provided and priv_key, whilst the encrypted session key is held in
	 * encrypted_key */
	if(1 != EVP_OpenInit(ctx, EVP_aes_256_cbc(), encrypted_key,
		encrypted_key_len, iv, priv_key))
		handleErrors();

	/* Provide the message to be decrypted, and obtain the plaintext output.
	 * EVP_OpenUpdate can be called multiple times if necessary
	 */
	if(1 != EVP_OpenUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
		handleErrors();
	plaintext_len = len;

	/* Finalise the decryption. Further plaintext bytes may be written at
	 * this stage.
	 */
	if(1 != EVP_OpenFinal(ctx, plaintext + len, &len)) handleErrors();
	plaintext_len += len;

	/* Clean up */
	EVP_CIPHER_CTX_free(ctx);

	return plaintext_len;
}

unsigned char* PLAINTEXT = (unsigned char*)"0123456789abcdefghijklmnopqrstuvwxyz";

int main(int argc, char* argv[])
{
  ERR_load_crypto_strings();

  OpenSSL_add_all_algorithms();

  OPENSSL_config(NULL);

  FILE* fp_pub = fopen(argv[1], "r");
  FILE* fp_priv = fopen(argv[2], "r");

  if (fp_pub && fp_priv) {
    EVP_PKEY** pub_key = malloc(8 * sizeof(EVP_PKEY));

    *(pub_key + 0) =  PEM_read_PUBKEY(fp_pub, NULL, NULL, NULL);

    unsigned char** ek = malloc(8 * sizeof(unsigned char*));
    *(ek + 0) = malloc(EVP_PKEY_size(*(pub_key + 0)) * sizeof(unsigned char));
    int* ekl = malloc(8 * sizeof(int));
    unsigned char* iv = malloc(EVP_MAX_IV_LENGTH * sizeof(unsigned char));

    fprintf(stderr, "plaintext: %s\n", PLAINTEXT);

    unsigned char ciphertext[16 * 2048];
    int ciphertext_len = envelope_seal(pub_key, PLAINTEXT, 36, ek, ekl, iv,
                                       ciphertext);
    fprintf(stderr, "cyphered text: %s\n", ciphertext);

    EVP_PKEY* priv_key = PEM_read_PrivateKey(fp_priv, NULL, NULL, NULL);

    unsigned char plaintext[1024];
    int plaintext_len = envelope_open(priv_key, ciphertext, ciphertext_len, *(ek + 0), *(ekl + 0), iv,
                                      plaintext);
    plaintext[plaintext_len] = '\0';
    fprintf(stderr, "plaintext check: %s\n", plaintext);

    free(iv);

    free(*(ek + 0));
    free(ek);

    EVP_PKEY_free(*(pub_key + 0));
    free(pub_key);

    EVP_PKEY_free(priv_key);

    fclose(fp_pub);
    fclose(fp_priv);
  }


  EVP_cleanup();

  CRYPTO_cleanup_all_ex_data();

  ERR_free_strings();

  return 0;
}
