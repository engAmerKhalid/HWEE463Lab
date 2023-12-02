#include <stdio.h>
#include <openssl/bn.h>
#include <stdlib.h>

void printBN(char *msg, BIGNUM *tmp) {
    char *number_str = BN_bn2hex(tmp); // Convert BIGNUM to hex
    printf("%s%s\n", msg, number_str); // Print hex
    OPENSSL_free(number_str); // Free memory
}

int main(int argc, char *argv[]) {
    BN_CTX *ctx = BN_CTX_new();

    BIGNUM *d = BN_new();
    BIGNUM *n = BN_new();
    BIGNUM *C = BN_new();
    BIGNUM *D = BN_new();

    // Assign values to n and C from hex strings
    BN_hex2bn(&n, "E103ABD94892E3E74AFD724BF28E78366D9676BCCC70118BD0AA1968DBB143D1");
    BN_hex2bn(&C, "858FF93C7C313EDC14E79A13EAF539D0893DACC7C70D335384965088E88AFC");

    // Assign the calculated private key (d) from Task 1
    BN_hex2bn(&d, "626C9D41C42C502A94D9078FFB8DE45A6BC97A3FA1D9E9D22DF82F35DEEA769");

    // Decrypt ciphertext using D = C^d mod n
    BN_mod_exp(D, C, d, n, ctx);

    // Convert the decrypted BIGNUM to a hex string and print it
    char *decrypted_hex = BN_bn2hex(D);
    printf("Decrypted Hex Message: %s\n", decrypted_hex);

    // Free allocated memory
    BN_CTX_free(ctx);
    BN_free(d);
    BN_free(n);
    BN_free(C);
    BN_free(D);
    OPENSSL_free(decrypted_hex);

    return EXIT_SUCCESS;
}
