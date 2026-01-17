#include "ssl_layer.h"
#include "common.h"
#include <openssl/err.h>
#include "logger.h"
#include "metrics.h"
#include <stdio.h>
#include <stdlib.h> // For malloc/free
#include <string.h>
#include <stdbool.h>

TAILQ_HEAD(ssl_layer_pool, ssl_layer);
static struct ssl_layer_pool g_ssl_layer_pool;
static ssl_layer_t g_ssl_layer_pool_storage[MAX_CONN_SIZE];
static bool g_ssl_layer_pool_initialized = false;

static void ssl_layer_pool_init(void) {
    if (g_ssl_layer_pool_initialized) return;

    TAILQ_INIT(&g_ssl_layer_pool);
    for (int i = 0; i < MAX_CONN_SIZE; i++) {
        TAILQ_INSERT_TAIL(&g_ssl_layer_pool, &g_ssl_layer_pool_storage[i], entries);
    }
    g_ssl_layer_pool_initialized = true;
}

static ssl_layer_t* get_ssl_layer_from_pool() {
    ssl_layer_pool_init();
    ssl_layer_t *layer = TAILQ_FIRST(&g_ssl_layer_pool);
    if (layer) {
        TAILQ_REMOVE(&g_ssl_layer_pool, layer, entries);
        memset(layer, 0, sizeof(ssl_layer_t));
    } else {
        LOG_WARN("SSL layer pool is empty.");
    }
    return layer;
}

static void return_ssl_layer_to_pool(ssl_layer_t *layer) {
    if (layer) {
        TAILQ_INSERT_HEAD(&g_ssl_layer_pool, layer, entries);
    }
}

static SSL_CTX *g_ssl_server_ctx = NULL;
static SSL_CTX *g_ssl_client_ctx = NULL;
int s_ex_data_idx = -1;

static int openssl_initialized = 0;

static void initialize_openssl_libraries() {
    if (!openssl_initialized) {
        SSL_library_init();
        OpenSSL_add_all_algorithms();
        SSL_load_error_strings();
        openssl_initialized = 1;
        if (s_ex_data_idx == -1) {
            s_ex_data_idx = SSL_get_ex_new_index(0, NULL, NULL, NULL, NULL);
            if (s_ex_data_idx == -1) {
                LOG_ERROR("SSL_get_ex_new_index failed");
                ERR_print_errors_fp(stderr);
            }
        }
    }
}

int ssl_layer_init_server(const char *cert_path, const char *key_path) {
    initialize_openssl_libraries();

    if (g_ssl_server_ctx) {
        return 0;
    }

    g_ssl_server_ctx = SSL_CTX_new(TLS_server_method());
    if (!g_ssl_server_ctx) {
        LOG_ERROR("SSL_CTX_new failed");
        ERR_print_errors_fp(stderr);
        return -1;
    }
    SSL_CTX_set_mode(g_ssl_server_ctx, SSL_MODE_ENABLE_PARTIAL_WRITE |
                     SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);

    if (SSL_CTX_use_certificate_file(g_ssl_server_ctx, cert_path,
                                     SSL_FILETYPE_PEM) <= 0) {
        LOG_ERROR("SSL_CTX_use_certificate_file failed");
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(g_ssl_server_ctx);
        g_ssl_server_ctx = NULL;
        return -1;
    }

    if (SSL_CTX_use_PrivateKey_file(g_ssl_server_ctx, key_path,
                                    SSL_FILETYPE_PEM) <= 0) {
        LOG_ERROR("SSL_CTX_use_PrivateKey_file failed");
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(g_ssl_server_ctx);
        g_ssl_server_ctx = NULL;
        return -1;
    }



    return 0;
}

int ssl_layer_init_client() {
    initialize_openssl_libraries();

    if (g_ssl_client_ctx) {
        return 0;
    }

    g_ssl_client_ctx = SSL_CTX_new(TLS_client_method());
    if (!g_ssl_client_ctx) {
        LOG_ERROR("SSL_CTX_new failed for client");
        ERR_print_errors_fp(stderr);
        return -1;
    }
    SSL_CTX_set_mode(g_ssl_client_ctx, SSL_MODE_ENABLE_PARTIAL_WRITE |
                     SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);



    return 0;
}

ssl_layer_t *
ssl_layer_create(int is_server,
                 on_handshake_complete_cb_t on_handshake_complete_cb,
                 on_encrypted_data_cb_t on_encrypted_data_cb,
                 on_decrypted_data_cb_t on_decrypted_data_cb) {
    ssl_layer_t *layer = get_ssl_layer_from_pool();
    if (!layer) {
        return NULL;
    }

    layer->on_handshake_complete_cb = on_handshake_complete_cb;
    layer->on_encrypted_data_cb = on_encrypted_data_cb;
    layer->on_decrypted_data_cb = on_decrypted_data_cb;

    if (is_server) {
        layer->ssl = SSL_new(g_ssl_server_ctx);
    } else {
        layer->ssl = SSL_new(g_ssl_client_ctx);
    }

    if (!layer->ssl) {
        return_ssl_layer_to_pool(layer);
        return NULL;
    }

    layer->rbio = BIO_new(BIO_s_mem());
    layer->wbio = BIO_new(BIO_s_mem());

    if (!layer->rbio || !layer->wbio) {
        if (layer->rbio) BIO_free(layer->rbio);
        if (layer->wbio) BIO_free(layer->wbio);
        SSL_free(layer->ssl);
        return_ssl_layer_to_pool(layer);
        LOG_ERROR("BIO_new failed");
        ERR_print_errors_fp(stderr); // Print OpenSSL errors if any during BIO creation
        return NULL;
    }

    SSL_set_bio(layer->ssl, layer->rbio, layer->wbio);
    if (is_server) {
        SSL_set_accept_state(layer->ssl);
    } else {
        SSL_set_connect_state(layer->ssl);
    }

    STATS_INC(ssl_connections_active);
    return layer;
}

void ssl_layer_destroy(ssl_layer_t *layer) {
    if (layer) {
        STATS_DEC(ssl_connections_active);
        SSL_free(layer->ssl);
        // BIOs are freed by SSL_free
        return_ssl_layer_to_pool(layer);
    }
}

ssl_handshake_status_t ssl_layer_handshake(ssl_layer_t *layer) {
    int ret = SSL_do_handshake(layer->ssl);
    if (ret == 1) {
        if (layer->on_handshake_complete_cb) {
            layer->on_handshake_complete_cb(layer);
        }
        return SSL_HANDSHAKE_OK;
    }

    int err = SSL_get_error(layer->ssl, ret);
    char buf[4096];
    int len = 0;

    switch (err) {
        case SSL_ERROR_WANT_READ:
        case SSL_ERROR_WANT_WRITE:
            len = BIO_read(layer->wbio, buf, sizeof(buf));
            if (len > 0) {
                STATS_ADD(ssl_bytes_encrypted, len);
                if (layer->on_encrypted_data_cb) {
                    layer->on_encrypted_data_cb(layer, buf, len);
                }
            } else if (len < 0) {
                LOG_DEBUG("BIO_read failed in handshake");
                //ERR_print_errors_fp(stderr);
                return SSL_HANDSHAKE_ERROR;
            }
            return (err == SSL_ERROR_WANT_READ) ? SSL_HANDSHAKE_WANT_READ
            : SSL_HANDSHAKE_WANT_WRITE;
        default:
            LOG_DEBUG("SSL_do_handshake failed with unhandled error");
            //ERR_print_errors_fp(stderr);
            STATS_INC(ssl_handshake_errors);
            return SSL_HANDSHAKE_ERROR;
    }
}

int ssl_layer_read_net_data(ssl_layer_t *layer, const void *data, int len) {
    int written = BIO_write(layer->rbio, data, len);

    if (written != len) {
        LOG_ERROR("BIO_write failed in read_net_data");
        ERR_print_errors_fp(stderr);
        return -1; // Failed to write all data to BIO
    }

    if (!SSL_is_init_finished(layer->ssl)) {
        LOG_DEBUG("ssl handshake");
        ssl_handshake_status_t hs_status = ssl_layer_handshake(layer);
        if (hs_status == SSL_HANDSHAKE_ERROR) {
            LOG_DEBUG("ssl_layer_handshake failed in read_net_data");
            //ERR_print_errors_fp(stderr);
            return -1; // Indicate an error during handshake
        }
        // Even if handshake is not complete, we continue to process any possible data
        // Return 0 only if no further processing is possible at this stage
        if (hs_status != SSL_HANDSHAKE_OK) {
            // Check if there is data to process after handshake attempt
            if (BIO_pending(layer->rbio) <= 0) {
                return 0; // No more data to process, wait for more network data
            }
        }
    }

    char buf[4096];
    int nbytes;
    int total_decrypted_bytes = 0;
    do {
        LOG_DEBUG("ssl data, call SSL_read");
        nbytes = SSL_read(layer->ssl, buf, sizeof(buf));
        if (nbytes > 0) {
            total_decrypted_bytes += nbytes;
            STATS_ADD(ssl_bytes_decrypted, nbytes);
            if (layer->on_decrypted_data_cb) {
                LOG_DEBUG("ssl data, call on_decrypted_data_cb");
                layer->on_decrypted_data_cb(layer, buf, nbytes);
                // The callback may have closed the connection and freed the layer.
                // To prevent a use-after-free, we stop processing more data in this cycle.
                break;
            }
        } else if (nbytes < 0) {
            int err = SSL_get_error(layer->ssl, nbytes);
            if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
                // No more data to read from SSL_read for now, but not an error.
                // Any pending encrypted data in wbio would have been handled by
                // handshake or will be handled when app data is written.
                break; // Exit loop, wait for more network data
            } else {
                //LOG_ERROR("SSL_read failed");
                //ERR_print_errors_fp(stderr);
                return -1; // Actual SSL_read error
            }
        } else { // nbytes == 0, meaning SSL_read indicates no more data from BIO
            break;
        }
    } while (BIO_pending(layer->rbio) > 0 || nbytes > 0); // Continue if more data in rbio or last read was successful

    return total_decrypted_bytes;
}

int ssl_layer_write_app_data(ssl_layer_t *layer, const void *data, int len) {

    LOG_DEBUG("ssl data, call ssl_layer_write_app_data, len: %d", len);
    int ret = SSL_write(layer->ssl, data, len);
    if (ret <= 0) {
        int err = SSL_get_error(layer->ssl, ret);
        if (err == SSL_ERROR_WANT_READ) {
            // This should not happen with memory BIOs
        } else {
            LOG_DEBUG("SSL_write failed");
            //ERR_print_errors_fp(stderr);
            return -1;
        }
    }

    char buf[4096];
    int nbytes;
    while ((nbytes = BIO_read(layer->wbio, buf, sizeof(buf))) > 0) {
        STATS_ADD(ssl_bytes_encrypted, nbytes);
        if (layer->on_encrypted_data_cb) {
            layer->on_encrypted_data_cb(layer, buf, nbytes);
        }
    }

    return ret;
}

int ssl_layer_shutdown(ssl_layer_t *layer) {
    int ret = SSL_shutdown(layer->ssl);
    if (ret == 0) {
        // Shutdown is not finished, need to call it again
        ret = SSL_shutdown(layer->ssl);
    }

    if (ret == 1) {
        // Shutdown is complete
        return 0;
    }

    int err = SSL_get_error(layer->ssl, ret);
    if (err == SSL_ERROR_WANT_READ) {
        char buf[4096];
        int len = BIO_read(layer->wbio, buf, sizeof(buf));
        if (len > 0) {
            if (layer->on_encrypted_data_cb) {
                layer->on_encrypted_data_cb(layer, buf, len);
            }
        }
    } else {
        LOG_ERROR("SSL_shutdown failed");
        ERR_print_errors_fp(stderr);
        return -1;
    }

    return 0;
}

void ssl_layer_cleanup() {
    if (g_ssl_server_ctx) {
        SSL_CTX_free(g_ssl_server_ctx);
        g_ssl_server_ctx = NULL;
    }
    if (g_ssl_client_ctx) {
        SSL_CTX_free(g_ssl_client_ctx);
        g_ssl_client_ctx = NULL;
    }
}
