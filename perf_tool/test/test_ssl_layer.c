#include "config.h"
#include "ssl_layer.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

// Mock callbacks
static int client_handshake_complete = 0;
static int server_handshake_complete = 0;
static int encrypted_data_len = 0;
static int decrypted_data_len = 0;

void on_handshake_complete_cb_client(ssl_layer_t *layer) {
  client_handshake_complete = 1;
}

void on_handshake_complete_cb_server(ssl_layer_t *layer) {
  server_handshake_complete = 1;
}

void on_encrypted_data_cb_test(ssl_layer_t *layer, const void *data, int len) {
  encrypted_data_len = len;
  // In a real test, we would inspect the data
}

void on_decrypted_data_cb_test(ssl_layer_t *layer, const void *data, int len) {
  decrypted_data_len = len;
  // In a real test, we would inspect the data
}

void test_ssl_layer_init_and_create() {
  printf("Running test: test_ssl_layer_init_and_create\n");

  // Create dummy cert and key files
  FILE *fp = fopen("test.crt", "w");
  fprintf(fp,
          "-----BEGIN CERTIFICATE-----\n"
          "MIIDpzCCAo+gAwIBAgIUfzlf+ESQwL2GNCUCHWGvSO2nHVcwDQYJKoZIhvcNAQEL\n"
          "BQAwYzELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAkNBMRYwFAYDVQQHDA1TYW4gRnJh\n"
          "bmNpc2NvMQ0wCwYDVQQKDARUZXN0MQ0wCwYDVQQLDARUZXN0MREwDwYDVQQDDAh0\n"
          "ZXN0LmNvbTAeFw0yNTExMjcwNTEyMzZaFw0yNjExMjcwNTEyMzZaMGMxCzAJBgNV\n"
          "BAYTAlVTMQswCQYDVQQIDAJDQTEWMBQGA1UEBwwNU2FuIEZyYW5jaXNjbzENMAsG\n"
          "A1UECgwEVGVzdDENMAsGA1UECwwEVGVzdDERMA8GA1UEAwwIdGVzdC5jb20wggEi\n"
          "MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDAj2GtM5YshdWUjxR18iipQiu4\n"
          "A7lFipRg9TfCYeeijD6/IrzZecBANUjrxER5LUe2gAwSBewAQRFrWIpxDkCfK65f\n"
          "4dgwhbgWBuRulMbJXjDCsEs+BQ/jNtmpWAiXtZ0kXzC4GIR1mxKDEznAJkBDMNcc\n"
          "UFlofZKWdFNKaB6TWBNMAHXabooycv7owy1Jwj3OamVzYmAtd3gKW2Jw0pksS6pV\n"
          "Ix0BhWfRyUQe49Dw84cokqfCOGtoCx20ErlbmtrcHaFa/b+yZR3hPt3EmSsQoxwx\n"
          "uThmM/3vUEO11rk6UwxtXLrC94HIrYPOMG1Z86CKR6bbeV4+zwC/Nd+i6gYfAgMB\n"
          "AAGjUzBRMB0GA1UdDgQWBBTinjRIUr+VQ/cSx1QHSYzrPJKSCDAfBgNVHSMEGDAW\n"
          "gBTinjRIUr+VQ/cSx1QHSYzrPJKSCDAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3\n"
          "DQEBCwUAA4IBAQAtQ8457nc5UNskflU/TFCmtpTZ8ghefLFHuWIAOM4Hlfs1mmcf\n"
          "ExlNGU8mpGDpC7VslHg0A7n1hbw/CNldA16RxBF1pqUVGzvxMKG/ks7j719zIAs/\n"
          "DC0otrwBvuLqBHOyrtbEbLlqv6KPms7kSARm4soew7Nlwyj9FnB3OawVhmgEj+Ak\n"
          "bvfEjHPU4QpHgXQkze5tKPWBPYwbfTRrQybvzzFnyZENpT6Me/iGxIt3aeyb+bfe\n"
          "9O66sSWeMttyJqpyw4HjC+SFJSPkT0L1v6CkjQ4uRuBvA+Zyqi/xBJKqxjXr0wpM\n"
          "OjTtoLAqPhmdI1vtcR7uKEwDkFVDzmt6KMrZ\n"
          "-----END CERTIFICATE-----\n");
  fclose(fp);

  fp = fopen("test.key", "w");
  fprintf(fp,
          "-----BEGIN PRIVATE KEY-----\n"
          "MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDAj2GtM5YshdWU\n"
          "jxR18iipQiu4A7lFipRg9TfCYeeijD6/IrzZecBANUjrxER5LUe2gAwSBewAQRFr\n"
          "WIpxDkCfK65f4dgwhbgWBuRulMbJXjDCsEs+BQ/jNtmpWAiXtZ0kXzC4GIR1mxKD\n"
          "EznAJkBDMNccUFlofZKWdFNKaB6TWBNMAHXabooycv7owy1Jwj3OamVzYmAtd3gK\n"
          "W2Jw0pksS6pVIx0BhWfRyUQe49Dw84cokqfCOGtoCx20ErlbmtrcHaFa/b+yZR3h\n"
          "Pt3EmSsQoxwxuThmM/3vUEO11rk6UwxtXLrC94HIrYPOMG1Z86CKR6bbeV4+zwC/\n"
          "Nd+i6gYfAgMBAAECggEADreGpsGqvcQMIvqyfMyMDgTy1BwOFMIMKBg7HD32Vvvd\n"
          "WdIHrp65sk6VlateSQf3E1GDBVJINhbDBDoeo+22blPc072Dk+XMatE5CTiRXteL\n"
          "kNL/f9chiTiVIcu1exQpf/D53MAcSOQYDJuIuOZTgq8gvwG8a5oup2rEPjYUoXx3\n"
          "VAe2zgm99zjAPMcphARGhxne9FwOOxLS+FqJt5xhnMcJG8ivQLx4L3lYSIjMXqt5\n"
          "wIvxpbkk+hjBzmRsV3mou1t/+24v07bgfmz64GVphEitqlF2PliKEi/AzTyEKggS\n"
          "b5b6U0SUTcR3++01/0QYti12651wBje9EW8MyPNA1QKBgQDAqseC2rdawzxvth1E\n"
          "PpyZZCvvJ9ls99yPgyiowwlCniYl2RwdfB/aP7k2qyYbJztU57T+4J8T1TQNkXmv\n"
          "JtYwscnZbKaeBKKZoHtFtRdsvq/AKPCFFqKmkeaO2lcDRVh68D4v95MkxMArysEL\n"
          "Rnh+gv7VuZd57VL2VDgO7G+5awKBgQD/25iZ15eQsrNwg3Uphr2w/F0BfTReDDHm\n"
          "tGMhj2waQ2QbcA18t+YUtR9WlndG/gVrJVd+zQeKmlMAIVNMF3t5OhmMtyimsmIj\n"
          "fKHCzZpmWazdYndsoJz/n6BCF1LVQCy1Zu7/WJzwKNTZchGxxA09W67gxJJkYfzx\n"
          "Ge8X0J5PHQKBgCi5sLSDQPCphjPi3erYBUgTOYoy9S2ocvHO+qA5odJ4FX44l03Q\n"
          "N/dtMtxQbxycPVlkJQkfN+D8VyVrE7qnTe07F3yjD9ElD63Dk2sXrVzqLcJDpRus\n"
          "vjLRclfN5Uimtt49vBdtkKfcAvb+w7F7curjC7TnpxI5zSiOgs78wV0DAoGATMLH\n"
          "P7CMyl6ysxjdd73y/zxXcvDrWyPxfLO14gWzexWo3Qp7IWXS43eLlWDDHEttuL2V\n"
          "SHeewZiXOjzFTtjktHQX4j25NnniM59asKUao4ZX9HtsNOzi7VYosGtq8Iu2Xh4p\n"
          "qfYd73dwlGRCpsCY8EWna8vN18wGJReQweZW+IkCgYBKTW6/QdRggNEIMTv4z8Bb\n"
          "ga4ulW69aRs7yle7WTXVrCTU71LNC/4K3bIyRauVgXdndGYB6nZuKjHXfIPuJCs/\n"
          "BSLkts8nd2ixbJHT5tF2yQRH7QgJTcMqK5qOaTSyZuqQkkhXBMAZD2zsqI7f4msU\n"
          "spM3sK/TpqLEklNkbEWuUQ==\n"
          "-----END PRIVATE KEY-----\n");
  fclose(fp);

  int ret = ssl_layer_init_server("test.crt", "test.key"); // 1 for is_server

  assert(ret == 0);

  ssl_layer_t *layer = ssl_layer_create(
      1, on_handshake_complete_cb_server, on_encrypted_data_cb_test,
      on_decrypted_data_cb_test); // 1 for is_server

  assert(layer != NULL);

  assert(layer->ssl != NULL);

  assert(layer->rbio != NULL);

  assert(layer->wbio != NULL);

  ssl_layer_destroy(layer);

  remove("test.crt");

  remove("test.key");

  printf("Test passed\n");
}

void test_ssl_layer_handshake() {
  printf("Running test: test_ssl_layer_handshake\n");
  printf("DEBUG: Entering test_ssl_layer_handshake\n");

  // Create dummy cert and key files
  FILE *fp = fopen("test.crt", "w");
  fprintf(fp,
          "-----BEGIN CERTIFICATE-----\n"
          "MIIDpzCCAo+gAwIBAgIUfzlf+ESQwL2GNCUCHWGvSO2nHVcwDQYJKoZIhvcNAQEL\n"
          "BQAwYzELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAkNBMRYwFAYDVQQHDA1TYW4gRnJh\n"
          "bmNpc2NvMQ0wCwYDVQQKDARUZXN0MQ0wCwYDVQQLDARUZXN0MREwDwYDVQQDDAh0\n"
          "ZXN0LmNvbTAeFw0yNTExMjcwNTEyMzZaFw0yNjExMjcwNTEyMzZaMGMxCzAJBgNV\n"
          "BAYTAlVTMQswCQYDVQQIDAJDQTEWMBQGA1UEBwwNU2FuIEZyYW5jaXNjbzENMAsG\n"
          "A1UECgwEVGVzdDENMAsGA1UECwwEVGVzdDERMA8GA1UEAwwIdGVzdC5jb20wggEi\n"
          "MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDAj2GtM5YshdWUjxR18iipQiu4\n"
          "A7lFipRg9TfCYeeijD6/IrzZecBANUjrxER5LUe2gAwSBewAQRFrWIpxDkCfK65f\n"
          "4dgwhbgWBuRulMbJXjDCsEs+BQ/jNtmpWAiXtZ0kXzC4GIR1mxKDEznAJkBDMNcc\n"
          "UFlofZKWdFNKaB6TWBNMAHXabooycv7owy1Jwj3OamVzYmAtd3gKW2Jw0pksS6pV\n"
          "Ix0BhWfRyUQe49Dw84cokqfCOGtoCx20ErlbmtrcHaFa/b+yZR3hPt3EmSsQoxwx\n"
          "uThmM/3vUEO11rk6UwxtXLrC94HIrYPOMG1Z86CKR6bbeV4+zwC/Nd+i6gYfAgMB\n"
          "AAGjUzBRMB0GA1UdDgQWBBTinjRIUr+VQ/cSx1QHSYzrPJKSCDAfBgNVHSMEGDAW\n"
          "gBTinjRIUr+VQ/cSx1QHSYzrPJKSCDAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3\n"
          "DQEBCwUAA4IBAQAtQ8457nc5UNskflU/TFCmtpTZ8ghefLFHuWIAOM4Hlfs1mmcf\n"
          "ExlNGU8mpGDpC7VslHg0A7n1hbw/CNldA16RxBF1pqUVGzvxMKG/ks7j719zIAs/\n"
          "DC0otrwBvuLqBHOyrtbEbLlqv6KPms7kSARm4soew7Nlwyj9FnB3OawVhmgEj+Ak\n"
          "bvfEjHPU4QpHgXQkze5tKPWBPYwbfTRrQybvzzFnyZENpT6Me/iGxIt3aeyb+bfe\n"
          "9O66sSWeMttyJqpyw4HjC+SFJSPkT0L1v6CkjQ4uRuBvA+Zyqi/xBJKqxjXr0wpM\n"
          "OjTtoLAqPhmdI1vtcR7uKEwDkFVDzmt6KMrZ\n"
          "-----END CERTIFICATE-----\n");
  fclose(fp);

  fp = fopen("test.key", "w");
  fprintf(fp,
          "-----BEGIN PRIVATE KEY-----\n"
          "MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDAj2GtM5YshdWU\n"
          "jxR18iipQiu4A7lFipRg9TfCYeeijD6/IrzZecBANUjrxER5LUe2gAwSBewAQRFr\n"
          "WIpxDkCfK65f4dgwhbgWBuRulMbJXjDCsEs+BQ/jNtmpWAiXtZ0kXzC4GIR1mxKD\n"
          "EznAJkBDMNccUFlofZKWdFNKaB6TWBNMAHXabooycv7owy1Jwj3OamVzYmAtd3gK\n"
          "W2Jw0pksS6pVIx0BhWfRyUQe49Dw84cokqfCOGtoCx20ErlbmtrcHaFa/b+yZR3h\n"
          "Pt3EmSsQoxwxuThmM/3vUEO11rk6UwxtXLrC94HIrYPOMG1Z86CKR6bbeV4+zwC/\n"
          "Nd+i6gYfAgMBAAECggEADreGpsGqvcQMIvqyfMyMDgTy1BwOFMIMKBg7HD32Vvvd\n"
          "WdIHrp65sk6VlateSQf3E1GDBVJINhbDBDoeo+22blPc072Dk+XMatE5CTiRXteL\n"
          "kNL/f9chiTiVIcu1exQpf/D53MAcSOQYDJuIuOZTgq8gvwG8a5oup2rEPjYUoXx3\n"
          "VAe2zgm99zjAPMcphARGhxne9FwOOxLS+FqJt5xhnMcJG8ivQLx4L3lYSIjMXqt5\n"
          "wIvxpbkk+hjBzmRsV3mou1t/+24v07bgfmz64GVphEitqlF2PliKEi/AzTyEKggS\n"
          "b5b6U0SUTcR3++01/0QYti12651wBje9EW8MyPNA1QKBgQDAqseC2rdawzxvth1E\n"
          "PpyZZCvvJ9ls99yPgyiowwlCniYl2RwdfB/aP7k2qyYbJztU57T+4J8T1TQNkXmv\n"
          "JtYwscnZbKaeBKKZoHtFtRdsvq/AKPCFFqKmkeaO2lcDRVh68D4v95MkxMArysEL\n"
          "Rnh+gv7VuZd57VL2VDgO7G+5awKBgQD/25iZ15eQsrNwg3Uphr2w/F0BfTReDDHm\n"
          "tGMhj2waQ2QbcA18t+YUtR9WlndG/gVrJVd+zQeKmlMAIVNMF3t5OhmMtyimsmIj\n"
          "fKHCzZpmWazdYndsoJz/n6BCF1LVQCy1Zu7/WJzwKNTZchGxxA09W67gxJJkYfzx\n"
          "Ge8X0J5PHQKBgCi5sLSDQPCphjPi3erYBUgTOYoy9S2ocvHO+qA5odJ4FX44l03Q\n"
          "N/dtMtxQbxycPVlkJQkfN+D8VyVrE7qnTe07F3yjD9ElD63Dk2sXrVzqLcJDpRus\n"
          "vjLRclfN5Uimtt49vBdtkKfcAvb+w7F7curjC7TnpxI5zSiOgs78wV0DAoGATMLH\n"
          "P7CMyl6ysxjdd73y/zxXcvDrWyPxfLO14gWzexWo3Qp7IWXS43eLlWDDHEttuL2V\n"
          "SHeewZiXOjzFTtjktHQX4j25NnniM59asKUao4ZX9HtsNOzi7VYosGtq8Iu2Xh4p\n"
          "qfYd73dwlGRCpsCY8EWna8vN18wGJReQweZW+IkCgYBKTW6/QdRggNEIMTv4z8Bb\n"
          "ga4ulW69aRs7yle7WTXVrCTU71LNC/4K3bIyRauVgXdndGYB6nZuKjHXfIPuJCs/\n"
          "BSLkts8nd2ixbJHT5tF2yQRH7QgJTcMqK5qOaTSyZuqQkkhXBMAZD2zsqI7f4msU\n"
          "spM3sK/TpqLEklNkbEWuUQ==\n"
          "-----END PRIVATE KEY-----\n");
  fclose(fp);

  // Ensure OpenSSL is initialized properly before each test
  SSL_library_init();
  OpenSSL_add_all_algorithms();
  SSL_load_error_strings();
  
  ssl_layer_cleanup(); // Call cleanup before init again

  ssl_layer_init_client();

  ssl_layer_t *client_layer = ssl_layer_create(
      0, on_handshake_complete_cb_client, on_encrypted_data_cb_test,
      on_decrypted_data_cb_test); // 0 for is_client
  assert(client_layer != NULL);

  // Set client SSL options to ensure compatibility
  SSL_set_options(client_layer->ssl, SSL_OP_ALL);
  SSL_set_cipher_list(client_layer->ssl, "ALL:eNULL");

  int ret = ssl_layer_init_server("test.crt", "test.key"); // 1 for is_server
  assert(ret == 0);

  ssl_layer_t *server_layer = ssl_layer_create(
      1, on_handshake_complete_cb_server, on_encrypted_data_cb_test,
      on_decrypted_data_cb_test); // 1 for is_server
  assert(server_layer != NULL);
  
  // Set server SSL options to ensure compatibility
  SSL_set_options(server_layer->ssl, SSL_OP_ALL);
  SSL_set_cipher_list(server_layer->ssl, "ALL:eNULL");

  char buf[4096];
  int len;
  int timeout = 0;
  int max_attempts = 20;

  printf("DEBUG: Starting SSL handshake loop\n");
  // Reset handshake completion flags
  client_handshake_complete = 0;
  server_handshake_complete = 0;

  // Ensure the client initiates the handshake by sending ClientHello
  printf("DEBUG: Initial client handshake attempt to send ClientHello\n");
  int client_ret = SSL_do_handshake(client_layer->ssl);
  if (client_ret == 1) {
    printf("DEBUG: Client handshake initiation succeeded immediately\n");
    client_handshake_complete = 1;
  } else {
    int err = SSL_get_error(client_layer->ssl, client_ret);
    char err_buf[256];
    ERR_error_string_n(ERR_get_error(), err_buf, sizeof(err_buf));
    printf("DEBUG: Client handshake initiation incomplete, return: %d, error: %d, SSL state: %d, detail: %s\n", 
           client_ret, err, SSL_get_state(client_layer->ssl), err_buf);
  }
  len = BIO_read(client_layer->wbio, buf, sizeof(buf));
  if (len > 0) {
    printf("DEBUG: Client sent initial data (%d bytes) - likely ClientHello\n", len);
    BIO_write(server_layer->rbio, buf, len);
    printf("DEBUG: Server received initial data (%d bytes) from client\n", len);
    // Force server handshake attempt immediately after receiving data
    int server_ret = SSL_do_handshake(server_layer->ssl);
    if (server_ret == 1) {
      printf("DEBUG: Server handshake completed immediately after receiving data\n");
      server_handshake_complete = 1;
    } else {
      int err = SSL_get_error(server_layer->ssl, server_ret);
      char err_buf[256];
      ERR_error_string_n(ERR_get_error(), err_buf, sizeof(err_buf));
      printf("DEBUG: Server handshake attempt after initial data, return: %d, error: %d, state: %d, detail: %s\n", 
             server_ret, err, SSL_get_state(server_layer->ssl), err_buf);
    }
    len = BIO_read(server_layer->wbio, buf, sizeof(buf));
    if (len > 0) {
      printf("DEBUG: Server sent data (%d bytes) after initial handshake attempt\n", len);
      BIO_write(client_layer->rbio, buf, len);
      printf("DEBUG: Client received data (%d bytes) from server\n", len);
    }
  } else {
    printf("DEBUG: ERROR - No initial data sent by client, SSL state: %d\n", SSL_get_state(client_layer->ssl));
  }

  while ((!client_handshake_complete || !server_handshake_complete) &&
         timeout < max_attempts) {
    printf("DEBUG: Handshake iteration %d/%d\n", timeout + 1, max_attempts);

    // Server side handshake step - process received data first
    printf("DEBUG: Server handshake attempt, SSL state: %d, BIO pending read: %d, write: %d\n", 
           SSL_get_state(server_layer->ssl), BIO_pending(server_layer->rbio), BIO_pending(server_layer->wbio));
    if (!server_handshake_complete) {
      int server_ret = SSL_do_handshake(server_layer->ssl);
      if (server_ret == 1) {
        printf("DEBUG: Server handshake completed\n");
        server_handshake_complete = 1;
      } else {
        int err = SSL_get_error(server_layer->ssl, server_ret);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
          printf("DEBUG: Server handshake waiting, return: %d, error: %d, state: %d\n", server_ret, err, SSL_get_state(server_layer->ssl));
        } else {
          char err_buf[256];
          ERR_error_string_n(ERR_get_error(), err_buf, sizeof(err_buf));
          printf("DEBUG: Server handshake step failed, return: %d, error: %d, detail: %s\n", server_ret, err, err_buf);
          break; // Exit loop on fatal error
        }
      }
    }
    len = BIO_read(server_layer->wbio, buf, sizeof(buf));
    if (len > 0) {
      printf("DEBUG: Server sent data (%d bytes) - likely ServerHello, Certificate, or subsequent messages\n", len);
      // Client receives data from server
      BIO_write(client_layer->rbio, buf, len);
      printf("DEBUG: Client received data (%d bytes) from server\n", len);
    } else {
      printf("DEBUG: No data sent by server in this iteration\n");
    }

    // Client side handshake step
    printf("DEBUG: Client handshake attempt, SSL state: %d, BIO pending read: %d, write: %d\n", 
           SSL_get_state(client_layer->ssl), BIO_pending(client_layer->rbio), BIO_pending(client_layer->wbio));
    if (!client_handshake_complete) {
      client_ret = SSL_do_handshake(client_layer->ssl);
      if (client_ret == 1) {
        printf("DEBUG: Client handshake completed\n");
        client_handshake_complete = 1;
      } else {
        int err = SSL_get_error(client_layer->ssl, client_ret);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
          printf("DEBUG: Client handshake waiting, return: %d, error: %d, state: %d\n", client_ret, err, SSL_get_state(client_layer->ssl));
        } else {
          char err_buf[256];
          ERR_error_string_n(ERR_get_error(), err_buf, sizeof(err_buf));
          printf("DEBUG: Client handshake step failed, return: %d, error: %d, detail: %s\n", client_ret, err, err_buf);
          break; // Exit loop on fatal error
        }
      }
    }
    len = BIO_read(client_layer->wbio, buf, sizeof(buf));
    if (len > 0) {
      printf("DEBUG: Client sent data (%d bytes) - likely handshake messages\n", len);
      // Server receives data from client
      BIO_write(server_layer->rbio, buf, len);
      printf("DEBUG: Server received data (%d bytes) from client\n", len);
    } else {
      printf("DEBUG: No data sent by client in this iteration\n");
    }

    // Check handshake status
    printf("DEBUG: Handshake status - Client complete: %d, Server complete: %d\n", 
           client_handshake_complete, server_handshake_complete);

    timeout++;
  }

  printf("DEBUG: Handshake loop ended. Timeout count: %d\n", timeout);
  assert(client_handshake_complete == 1);
  assert(server_handshake_complete == 1);

  ssl_layer_destroy(client_layer);
  ssl_layer_destroy(server_layer);

  remove("test.crt");
  remove("test.key");

  printf("Test passed\n");
}

void test_ssl_layer_data_communication() {
  printf("Running test: test_ssl_layer_data_communication\n");
  printf("DEBUG: Entering test_ssl_layer_data_communication\n");

  // Create dummy cert and key files
  FILE *fp = fopen("test.crt", "w");
  fprintf(fp,
          "-----BEGIN CERTIFICATE-----\n"
          "MIIDpzCCAo+gAwIBAgIUfzlf+ESQwL2GNCUCHWGvSO2nHVcwDQYJKoZIhvcNAQEL\n"
          "BQAwYzELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAkNBMRYwFAYDVQQHDA1TYW4gRnJh\n"
          "bmNpc2NvMQ0wCwYDVQQKDARUZXN0MQ0wCwYDVQQLDARUZXN0MREwDwYDVQQDDAh0\n"
          "ZXN0LmNvbTAeFw0yNTExMjcwNTEyMzZaFw0yNjExMjcwNTEyMzZaMGMxCzAJBgNV\n"
          "BAYTAlVTMQswCQYDVQQIDAJDQTEWMBQGA1UEBwwNU2FuIEZyYW5jaXNjbzENMAsG\n"
          "A1UECgwEVGVzdDENMAsGA1UECwwEVGVzdDERMA8GA1UEAwwIdGVzdC5jb20wggEi\n"
          "MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDAj2GtM5YshdWUjxR18iipQiu4\n"
          "A7lFipRg9TfCYeeijD6/IrzZecBANUjrxER5LUe2gAwSBewAQRFrWIpxDkCfK65f\n"
          "4dgwhbgWBuRulMbJXjDCsEs+BQ/jNtmpWAiXtZ0kXzC4GIR1mxKDEznAJkBDMNcc\n"
          "UFlofZKWdFNKaB6TWBNMAHXabooycv7owy1Jwj3OamVzYmAtd3gKW2Jw0pksS6pV\n"
          "Ix0BhWfRyUQe49Dw84cokqfCOGtoCx20ErlbmtrcHaFa/b+yZR3hPt3EmSsQoxwx\n"
          "uThmM/3vUEO11rk6UwxtXLrC94HIrYPOMG1Z86CKR6bbeV4+zwC/Nd+i6gYfAgMB\n"
          "AAGjUzBRMB0GA1UdDgQWBBTinjRIUr+VQ/cSx1QHSYzrPJKSCDAfBgNVHSMEGDAW\n"
          "gBTinjRIUr+VQ/cSx1QHSYzrPJKSCDAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3\n"
          "DQEBCwUAA4IBAQAtQ8457nc5UNskflU/TFCmtpTZ8ghefLFHuWIAOM4Hlfs1mmcf\n"
          "ExlNGU8mpGDpC7VslHg0A7n1hbw/CNldA16RxBF1pqUVGzvxMKG/ks7j719zIAs/\n"
          "DC0otrwBvuLqBHOyrtbEbLlqv6KPms7kSARm4soew7Nlwyj9FnB3OawVhmgEj+Ak\n"
          "bvfEjHPU4QpHgXQkze5tKPWBPYwbfTRrQybvzzFnyZENpT6Me/iGxIt3aeyb+bfe\n"
          "9O66sSWeMttyJqpyw4HjC+SFJSPkT0L1v6CkjQ4uRuBvA+Zyqi/xBJKqxjXr0wpM\n"
          "OjTtoLAqPhmdI1vtcR7uKEwDkFVDzmt6KMrZ\n"
          "-----END CERTIFICATE-----\n");
  fclose(fp);

  fp = fopen("test.key", "w");
  fprintf(fp,
          "-----BEGIN PRIVATE KEY-----\n"
          "MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDAj2GtM5YshdWU\n"
          "jxR18iipQiu4A7lFipRg9TfCYeeijD6/IrzZecBANUjrxER5LUe2gAwSBewAQRFr\n"
          "WIpxDkCfK65f4dgwhbgWBuRulMbJXjDCsEs+BQ/jNtmpWAiXtZ0kXzC4GIR1mxKD\n"
          "EznAJkBDMNccUFlofZKWdFNKaB6TWBNMAHXabooycv7owy1Jwj3OamVzYmAtd3gK\n"
          "W2Jw0pksS6pVIx0BhWfRyUQe49Dw84cokqfCOGtoCx20ErlbmtrcHaFa/b+yZR3h\n"
          "Pt3EmSsQoxwxuThmM/3vUEO11rk6UwxtXLrC94HIrYPOMG1Z86CKR6bbeV4+zwC/\n"
          "Nd+i6gYfAgMBAAECggEADreGpsGqvcQMIvqyfMyMDgTy1BwOFMIMKBg7HD32Vvvd\n"
          "WdIHrp65sk6VlateSQf3E1GDBVJINhbDBDoeo+22blPc072Dk+XMatE5CTiRXteL\n"
          "kNL/f9chiTiVIcu1exQpf/D53MAcSOQYDJuIuOZTgq8gvwG8a5oup2rEPjYUoXx3\n"
          "VAe2zgm99zjAPMcphARGhxne9FwOOxLS+FqJt5xhnMcJG8ivQLx4L3lYSIjMXqt5\n"
          "wIvxpbkk+hjBzmRsV3mou1t/+24v07bgfmz64GVphEitqlF2PliKEi/AzTyEKggS\n"
          "b5b6U0SUTcR3++01/0QYti12651wBje9EW8MyPNA1QKBgQDAqseC2rdawzxvth1E\n"
          "PpyZZCvvJ9ls99yPgyiowwlCniYl2RwdfB/aP7k2qyYbJztU57T+4J8T1TQNkXmv\n"
          "JtYwscnZbKaeBKKZoHtFtRdsvq/AKPCFFqKmkeaO2lcDRVh68D4v95MkxMArysEL\n"
          "Rnh+gv7VuZd57VL2VDgO7G+5awKBgQD/25iZ15eQsrNwg3Uphr2w/F0BfTReDDHm\n"
          "tGMhj2waQ2QbcA18t+YUtR9WlndG/gVrJVd+zQeKmlMAIVNMF3t5OhmMtyimsmIj\n"
          "fKHCzZpmWazdYndsoJz/n6BCF1LVQCy1Zu7/WJzwKNTZchGxxA09W67gxJJkYfzx\n"
          "Ge8X0J5PHQKBgCi5sLSDQPCphjPi3erYBUgTOYoy9S2ocvHO+qA5odJ4FX44l03Q\n"
          "N/dtMtxQbxycPVlkJQkfN+D8VyVrE7qnTe07F3yjD9ElD63Dk2sXrVzqLcJDpRus\n"
          "vjLRclfN5Uimtt49vBdtkKfcAvb+w7F7curjC7TnpxI5zSiOgs78wV0DAoGATMLH\n"
          "P7CMyl6ysxjdd73y/zxXcvDrWyPxfLO14gWzexWo3Qp7IWXS43eLlWDDHEttuL2V\n"
          "SHeewZiXOjzFTtjktHQX4j25NnniM59asKUao4ZX9HtsNOzi7VYosGtq8Iu2Xh4p\n"
          "qfYd73dwlGRCpsCY8EWna8vN18wGJReQweZW+IkCgYBKTW6/QdRggNEIMTv4z8Bb\n"
          "ga4ulW69aRs7yle7WTXVrCTU71LNC/4K3bIyRauVgXdndGYB6nZuKjHXfIPuJCs/\n"
          "BSLkts8nd2ixbJHT5tF2yQRH7QgJTcMqK5qOaTSyZuqQkkhXBMAZD2zsqI7f4msU\n"
          "spM3sK/TpqLEklNkbEWuUQ==\n"
          "-----END PRIVATE KEY-----\n");
  fclose(fp);

  // Ensure OpenSSL is initialized properly before each test
  SSL_library_init();
  OpenSSL_add_all_algorithms();
  SSL_load_error_strings();
  
  ssl_layer_cleanup(); // Call cleanup before init again

  ssl_layer_init_client();

  ssl_layer_t *client_layer = ssl_layer_create(
      0, on_handshake_complete_cb_client, on_encrypted_data_cb_test,
      on_decrypted_data_cb_test); // 0 for is_client
  assert(client_layer != NULL);

  // Set client SSL options to ensure compatibility
  SSL_set_options(client_layer->ssl, SSL_OP_ALL);
  SSL_set_cipher_list(client_layer->ssl, "ALL:eNULL");

  int ret = ssl_layer_init_server("test.crt", "test.key"); // 1 for is_server
  assert(ret == 0);

  ssl_layer_t *server_layer = ssl_layer_create(
      1, on_handshake_complete_cb_server, on_encrypted_data_cb_test,
      on_decrypted_data_cb_test); // 1 for is_server
  assert(server_layer != NULL);
  
  // Set server SSL options to ensure compatibility
  SSL_set_options(server_layer->ssl, SSL_OP_ALL);
  SSL_set_cipher_list(server_layer->ssl, "ALL:eNULL");

  char buf[4096];
  int len;
  int timeout = 0;
  int max_attempts = 20;

  printf("DEBUG: Starting SSL handshake loop\n");
  // Reset handshake completion flags
  client_handshake_complete = 0;
  server_handshake_complete = 0;

  // Ensure the client initiates the handshake by sending ClientHello
  printf("DEBUG: Initial client handshake attempt to send ClientHello\n");
  int client_ret = SSL_do_handshake(client_layer->ssl);
  if (client_ret == 1) {
    printf("DEBUG: Client handshake initiation succeeded immediately\n");
    client_handshake_complete = 1;
  } else {
    int err = SSL_get_error(client_layer->ssl, client_ret);
    char err_buf[256];
    ERR_error_string_n(ERR_get_error(), err_buf, sizeof(err_buf));
    printf("DEBUG: Client handshake initiation incomplete, return: %d, error: %d, SSL state: %d, detail: %s\n", 
           client_ret, err, SSL_get_state(client_layer->ssl), err_buf);
  }
  len = BIO_read(client_layer->wbio, buf, sizeof(buf));
  if (len > 0) {
    printf("DEBUG: Client sent initial data (%d bytes) - likely ClientHello\n", len);
    BIO_write(server_layer->rbio, buf, len);
    printf("DEBUG: Server received initial data (%d bytes) from client\n", len);
    // Force server handshake attempt immediately after receiving data
    int server_ret = SSL_do_handshake(server_layer->ssl);
    if (server_ret == 1) {
      printf("DEBUG: Server handshake completed immediately after receiving data\n");
      server_handshake_complete = 1;
    } else {
      int err = SSL_get_error(server_layer->ssl, server_ret);
      char err_buf[256];
      ERR_error_string_n(ERR_get_error(), err_buf, sizeof(err_buf));
      printf("DEBUG: Server handshake attempt after initial data, return: %d, error: %d, state: %d, detail: %s\n", 
             server_ret, err, SSL_get_state(server_layer->ssl), err_buf);
    }
    len = BIO_read(server_layer->wbio, buf, sizeof(buf));
    if (len > 0) {
      printf("DEBUG: Server sent data (%d bytes) after initial handshake attempt\n", len);
      BIO_write(client_layer->rbio, buf, len);
      printf("DEBUG: Client received data (%d bytes) from server\n", len);
    }
  } else {
    printf("DEBUG: ERROR - No initial data sent by client, SSL state: %d\n", SSL_get_state(client_layer->ssl));
  }

  while ((!client_handshake_complete || !server_handshake_complete) &&
         timeout < max_attempts) {
    printf("DEBUG: Handshake iteration %d/%d\n", timeout + 1, max_attempts);

    // Server side handshake step - process received data first
    printf("DEBUG: Server handshake attempt, SSL state: %d, BIO pending read: %d, write: %d\n", 
           SSL_get_state(server_layer->ssl), BIO_pending(server_layer->rbio), BIO_pending(server_layer->wbio));
    if (!server_handshake_complete) {
      int server_ret = SSL_do_handshake(server_layer->ssl);
      if (server_ret == 1) {
        printf("DEBUG: Server handshake completed\n");
        server_handshake_complete = 1;
      } else {
        int err = SSL_get_error(server_layer->ssl, server_ret);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
          printf("DEBUG: Server handshake waiting, return: %d, error: %d, state: %d\n", server_ret, err, SSL_get_state(server_layer->ssl));
        } else {
          char err_buf[256];
          ERR_error_string_n(ERR_get_error(), err_buf, sizeof(err_buf));
          printf("DEBUG: Server handshake step failed, return: %d, error: %d, detail: %s\n", server_ret, err, err_buf);
          break; // Exit loop on fatal error
        }
      }
    }
    len = BIO_read(server_layer->wbio, buf, sizeof(buf));
    if (len > 0) {
      printf("DEBUG: Server sent data (%d bytes) - likely ServerHello, Certificate, or subsequent messages\n", len);
      // Client receives data from server
      BIO_write(client_layer->rbio, buf, len);
      printf("DEBUG: Client received data (%d bytes) from server\n", len);
    } else {
      printf("DEBUG: No data sent by server in this iteration\n");
    }

    // Client side handshake step
    printf("DEBUG: Client handshake attempt, SSL state: %d, BIO pending read: %d, write: %d\n", 
           SSL_get_state(client_layer->ssl), BIO_pending(client_layer->rbio), BIO_pending(client_layer->wbio));
    if (!client_handshake_complete) {
      client_ret = SSL_do_handshake(client_layer->ssl);
      if (client_ret == 1) {
        printf("DEBUG: Client handshake completed\n");
        client_handshake_complete = 1;
      } else {
        int err = SSL_get_error(client_layer->ssl, client_ret);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
          printf("DEBUG: Client handshake waiting, return: %d, error: %d, state: %d\n", client_ret, err, SSL_get_state(client_layer->ssl));
        } else {
          char err_buf[256];
          ERR_error_string_n(ERR_get_error(), err_buf, sizeof(err_buf));
          printf("DEBUG: Client handshake step failed, return: %d, error: %d, detail: %s\n", client_ret, err, err_buf);
          break; // Exit loop on fatal error
        }
      }
    }
    len = BIO_read(client_layer->wbio, buf, sizeof(buf));
    if (len > 0) {
      printf("DEBUG: Client sent data (%d bytes) - likely handshake messages\n", len);
      // Server receives data from client
      BIO_write(server_layer->rbio, buf, len);
      printf("DEBUG: Server received data (%d bytes) from client\n", len);
    } else {
      printf("DEBUG: No data sent by client in this iteration\n");
    }

    // Check handshake status
    printf("DEBUG: Handshake status - Client complete: %d, Server complete: %d\n", 
           client_handshake_complete, server_handshake_complete);

    timeout++;
  }

  printf("DEBUG: Handshake loop ended. Timeout count: %d\n", timeout);
  assert(client_handshake_complete == 1);
  assert(server_handshake_complete == 1);

  // Reset data length counters
  encrypted_data_len = 0;
  decrypted_data_len = 0;

  // Test data communication from client to server
  const char *client_message = "Hello from client!";
  int client_msg_len = strlen(client_message) + 1; // Include null terminator
  printf("DEBUG: Client sending message: %s\n", client_message);
  int written = SSL_write(client_layer->ssl, client_message, client_msg_len);
  assert(written == client_msg_len);
  
  len = BIO_read(client_layer->wbio, buf, sizeof(buf));
  assert(len > 0);
  printf("DEBUG: Client sent encrypted data (%d bytes)\n", len);
  BIO_write(server_layer->rbio, buf, len);
  printf("DEBUG: Server received encrypted data (%d bytes) from client\n", len);
  
  char server_received[4096];
  int server_read = SSL_read(server_layer->ssl, server_received, sizeof(server_received));
  assert(server_read == client_msg_len);
  assert(strcmp(server_received, client_message) == 0);
  printf("DEBUG: Server received and decrypted message: %s\n", server_received);

  // Test data communication from server to client
  const char *server_message = "Hello from server!";
  int server_msg_len = strlen(server_message) + 1; // Include null terminator
  printf("DEBUG: Server sending message: %s\n", server_message);
  written = SSL_write(server_layer->ssl, server_message, server_msg_len);
  assert(written == server_msg_len);
  
  len = BIO_read(server_layer->wbio, buf, sizeof(buf));
  assert(len > 0);
  printf("DEBUG: Server sent encrypted data (%d bytes)\n", len);
  BIO_write(client_layer->rbio, buf, len);
  printf("DEBUG: Client received encrypted data (%d bytes) from server\n", len);
  
  char client_received[4096];
  int client_read = SSL_read(client_layer->ssl, client_received, sizeof(client_received));
  assert(client_read == server_msg_len);
  assert(strcmp(client_received, server_message) == 0);
  printf("DEBUG: Client received and decrypted message: %s\n", client_received);

  ssl_layer_destroy(client_layer);
  ssl_layer_destroy(server_layer);

  remove("test.crt");
  remove("test.key");

  printf("Test passed\n");
}

int main() {
    // Initialize OpenSSL
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    
    test_ssl_layer_init_and_create();
    test_ssl_layer_handshake();
    test_ssl_layer_data_communication();
    ssl_layer_cleanup(); // Call cleanup at the end of all tests
    return 0;
}
