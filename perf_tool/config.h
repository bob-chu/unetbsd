#ifndef CONFIG_H
#define CONFIG_H

#include <stdint.h>

// Struct for test scheduler configuration
typedef struct {
    int prepare_duration_sec;
    int ramp_up_duration_sec;
    int sustain_duration_sec;
    int ramp_down_duration_sec;
    int close_duration_sec;
} scheduler_config_t;

// Struct for test objective configuration
typedef struct {
    char *type;
    int value;
    int requests_per_second;
    int requests_per_connection;
} objective_config_t;

// Struct for network configuration
typedef struct {
    char *mac_address;
    char *src_ip_start;
    char *src_ip_end;
    char *dst_ip_start;
    char *dst_ip_end;
    char *protocol;
    int src_port_start;
    int src_port_end;
    int dst_port_start;
    int dst_port_end;
} network_config_t;

// Struct for payload configuration
typedef struct {
    char *data;
    int size;
} payload_config_t;

// Struct for HTTP configuration
typedef struct {
    char *client_request_path;
    int response_size_hello;    // Response size for /hello path
    int response_size_another;  // Response size for /another path
    int response_size_default;  // Default response size for other paths
} http_config_t;

// Main performance test configuration struct
typedef struct {
    scheduler_config_t scheduler;
    objective_config_t objective;
    network_config_t network;
    payload_config_t client_payload;
    payload_config_t server_response;
    http_config_t http_config;
    struct {
        int mtu;
    } interface;
} perf_config_t;

// Function to parse the configuration file
int parse_config(const char *file_path, perf_config_t *config);

// Function to free memory allocated for the configuration
void free_config(perf_config_t *config);

#endif // CONFIG_H
