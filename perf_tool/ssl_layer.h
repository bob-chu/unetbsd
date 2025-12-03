#ifndef __SSL_LAYER_H__
#define __SSL_LAYER_H__

#include <openssl/ssl.h>

typedef struct ssl_layer ssl_layer_t;

typedef void (*on_handshake_complete_cb_t)(ssl_layer_t *layer);
typedef void (*on_encrypted_data_cb_t)(ssl_layer_t *layer, const void *data,
                                       int len);
typedef void (*on_decrypted_data_cb_t)(ssl_layer_t *layer, const void *data,
                                       int len);

struct ssl_layer {
  SSL *ssl;
  BIO *rbio;
  BIO *wbio;
  on_handshake_complete_cb_t on_handshake_complete_cb;
  on_encrypted_data_cb_t on_encrypted_data_cb;
  on_decrypted_data_cb_t on_decrypted_data_cb;
};

int ssl_layer_init_server(const char *cert_path, const char *key_path);
int ssl_layer_init_client();
ssl_layer_t *
ssl_layer_create(int is_server,
                 on_handshake_complete_cb_t on_handshake_complete_cb,
                 on_encrypted_data_cb_t on_encrypted_data_cb,
                 on_decrypted_data_cb_t on_decrypted_data_cb);
void ssl_layer_destroy(ssl_layer_t *layer);

typedef enum {
  SSL_HANDSHAKE_OK = 0,
  SSL_HANDSHAKE_WANT_READ,
  SSL_HANDSHAKE_WANT_WRITE,
  SSL_HANDSHAKE_ERROR
} ssl_handshake_status_t;

ssl_handshake_status_t ssl_layer_handshake(ssl_layer_t *layer);
int ssl_layer_write_app_data(ssl_layer_t *layer, const void *data, int len);
int ssl_layer_read_net_data(ssl_layer_t *layer, const void *data, int len);
int ssl_layer_shutdown(ssl_layer_t *layer);

extern int s_ex_data_idx;
void ssl_layer_cleanup();

#endif /* __SSL_LAYER_H__ */
