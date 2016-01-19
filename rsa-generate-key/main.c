#include <stdlib.h>
#include <stdio.h>

#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/pem.h>

static int bn_callback_func(int p, int n, void* arg) {
  char c = '*';

  if (p == 0) c = '.';    // found potential prime
  if (p == 1) c = '+';    // testing potential prime
  if (p == 2) c = '+';    // potential prime rejected
  if (p == 3) c = '\n';    // potential prime accepted
  fprintf(stderr, "%c", c);

  return 1;
}

int main(int argc, char* argv[]) {

  BIGNUM* bn = BN_new();
  BN_set_word(bn, RSA_F4);

  RSA* rsa = RSA_new();
  BN_GENCB bn_callback ;
  BN_GENCB_set(&bn_callback, bn_callback_func, NULL);

  if (RSA_generate_key_ex(rsa, 2048, bn, &bn_callback)) {
    RSA_print_fp(stdout, rsa, 4);

    FILE* fp = fopen("id_rsa.key", "w");
    PEM_write_RSAPrivateKey(fp, rsa, EVP_aes_256_cbc(), NULL, 0, NULL, NULL);
    fclose(fp);

    FILE* fp_pub = fopen("id_rsa.pub", "w");
    PEM_write_RSA_PUBKEY(fp_pub, rsa);
    fclose(fp_pub);
  }

  RSA_free(rsa);

  BN_free(bn);


  int err  = ERR_get_error();
  if (err) {
    fprintf(stderr, "ERROR: %s\n", ERR_error_string(err, NULL));
  } else {
    fprintf(stderr, "OK\n");
  }


  return 0;

}
