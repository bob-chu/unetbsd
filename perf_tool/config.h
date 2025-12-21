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
  int client_ring_idx;
  int client_lcore_id;
  int core_id;
  int is_dpdk_client; // New flag to indicate DPDK client mode
} dpdk_config_t;

typedef struct {
  char *data;
  int size;
} payload_config_t;

typedef struct {
  char *path;
  char **request_headers;
  int request_headers_count;
  char **response_headers;
  int response_headers_count;
  int response_body_size;
} http_path_config_t;

typedef struct {
  int use_https;
  char *cert_path;
  char *key_path;
  http_path_config_t *paths;
  int paths_count;
} http_config_t;

typedef struct {
  scheduler_config_t scheduler;
  objective_config_t objective;
  l2_config_t l2;
  l3_config_t l3;
  l4_config_t l4;
  dpdk_config_t dpdk_client;
  dpdk_config_t dpdk_server;
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
