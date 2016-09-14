#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/bio.h>
#include <openssl/pem.h>

int main(int argc, char* argv[]) {

/*
  BIO* bio_pub = BIO_new_file("id_rsa.pub", "w");
  BIO* bio_key = BIO_new_file("id_rsa.key", "w");
*/
/*
  BIO* bio_pub = BIO_new(BIO_s_mem());
  BIO* bio_key = BIO_new(BIO_s_mem());
*/

  EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);

  if (ctx) {
    if (EVP_PKEY_keygen_init(ctx) > 0) {
      if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) > 0) {

        EVP_PKEY *pkey = NULL;
        if (EVP_PKEY_keygen(ctx, &pkey) > 0) {

                FILE* fp = fopen("id_rsa.key", "w");
                PEM_write_PrivateKey(fp, pkey, NULL, NULL, 0, NULL, NULL);
                fclose(fp);

                fp = fopen("id_rsa.pub", "w");
                PEM_write_PUBKEY(fp, pkey);
                fclose(fp);

/*
          char buf[2048];

          EVP_PKEY_print_private(bio_key, pkey, 0, NULL);
          memset(buf, 0, 2048);
          BIO_read(bio_key, buf, 2048);
          printf("%s\n\n", buf);
          BIO_free(bio_key);

          EVP_PKEY_print_public(bio_pub, pkey, 0, NULL);
          memset(buf, 0, 2048);
          BIO_read(bio_pub, buf, 2048);
          printf("*****************************************\n%s", buf);
          BIO_free(bio_pub);
*/
          EVP_PKEY_free(pkey);
        }

      }
    }

    EVP_PKEY_CTX_free(ctx);
  }

  int err  = ERR_get_error();
  if (err) {
    fprintf(stderr, "ERROR: %s\n", ERR_error_string(err, NULL));
  } else {
    fprintf(stderr, "OK\n");
  }

  return 0;
}
