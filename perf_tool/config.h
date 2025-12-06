#ifndef CONFIG_H
#define CONFIG_H

#include <stdint.h>

typedef struct {
  int prepare_duration_sec;
  int ramp_up_duration_sec;
  int sustain_duration_sec;
  int ramp_down_duration_sec;
  int close_duration_sec;
} scheduler_config_t;

typedef struct {
  char *type;
  int value;
  int requests_per_second;
  int requests_per_connection;
} objective_config_t;

typedef struct {
  char *mac_address;
} l2_config_t;

typedef struct {
  char *src_ip_start;
  char *src_ip_end;
  char *dst_ip_start;
  char *dst_ip_end;
} l3_config_t;

typedef struct {
  char *protocol;
  int src_port_start;
  int src_port_end;
  int dst_port_start;
  int dst_port_end;
} l4_config_t;

typedef struct {
  char *iface;
  char *args;
} dpdk_config_t;

typedef struct {
  char *data;
  int size;
} payload_config_t;

typedef struct {
  char *client_request_path;
  int response_size_hello;
  int response_size_another;
  int response_size_default;
  int use_https;
  char *cert_path;
  char *key_path;
} http_config_t;

typedef struct {
  scheduler_config_t scheduler;
  objective_config_t objective;
  l2_config_t l2;
  l3_config_t l3;
  l4_config_t l4;
  dpdk_config_t dpdk;
  payload_config_t client_payload;
  payload_config_t server_response;
  http_config_t http_config;
  int use_https;
  char *cert_path;
  char *key_path;
  struct {
    int mtu;
  } interface;
} perf_config_t;

int parse_config(const char *file_path, perf_config_t *config);
void free_config(perf_config_t *config);

#endif // CONFIG_H
