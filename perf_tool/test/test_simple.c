#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

void test_simple_init() {
    printf("Running test: test_simple_init\n");

    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    assert(ctx != NULL);

    SSL_CTX_free(ctx);

    printf("Test passed\n");
}

int main() {
    test_simple_init();
    return 0;
}
