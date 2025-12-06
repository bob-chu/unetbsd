#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "config.h"
#include "cJSON.h"

// Helper function to safely get a string from a cJSON object
static char* get_string_from_json(cJSON *json, const char *key) {
    cJSON *item = cJSON_GetObjectItemCaseSensitive(json, key);
    if (cJSON_IsString(item) && (item->valuestring != NULL)) {
        return strdup(item->valuestring);
    }
    return NULL;
}

// Helper function to safely get an integer from a cJSON object
static int get_int_from_json(cJSON *json, const char *key) {
    cJSON *item = cJSON_GetObjectItemCaseSensitive(json, key);
    if (cJSON_IsNumber(item)) {
        return item->valueint;
    }
    return 0; // Default value
}

int parse_config(const char *file_path, perf_config_t *config) {
    char *buffer = NULL;
    long length;
    FILE *f = fopen(file_path, "rb");

    if (!f) {
        fprintf(stderr, "Could not open %s\n", file_path);
        return -1;
    }

    fseek(f, 0, SEEK_END);
    length = ftell(f);
    fseek(f, 0, SEEK_SET);
    buffer = (char*)malloc(length + 1);
    if (buffer) {
        fread(buffer, 1, length, f);
    }
    fclose(f);

    if (!buffer) {
        fprintf(stderr, "Could not read file %s\n", file_path);
        return -1;
    }
    buffer[length] = '\0';

    cJSON *json = cJSON_Parse(buffer);
    free(buffer);
    if (json == NULL) {
        const char *error_ptr = cJSON_GetErrorPtr();
        if (error_ptr != NULL) {
            fprintf(stderr, "Error before: %s\n", error_ptr);
        }
        return -1;
    }

    // Parse scheduler config
    cJSON *scheduler_json = cJSON_GetObjectItemCaseSensitive(json, "scheduler");
    if (scheduler_json) {
        config->scheduler.prepare_duration_sec = get_int_from_json(scheduler_json, "prepare_duration_sec");
        config->scheduler.ramp_up_duration_sec = get_int_from_json(scheduler_json, "ramp_up_duration_sec");
        config->scheduler.sustain_duration_sec = get_int_from_json(scheduler_json, "sustain_duration_sec");
        config->scheduler.ramp_down_duration_sec = get_int_from_json(scheduler_json, "ramp_down_duration_sec");
        config->scheduler.close_duration_sec = get_int_from_json(scheduler_json, "close_duration_sec");
    }

    // Parse objective config
    cJSON *objective_json = cJSON_GetObjectItemCaseSensitive(json, "objective");
    if (objective_json) {
        config->objective.type = get_string_from_json(objective_json, "type");
        config->objective.value = get_int_from_json(objective_json, "value");
        cJSON *rps_item = cJSON_GetObjectItemCaseSensitive(objective_json, "requests_per_second");
        if (cJSON_IsNumber(rps_item)) {
            config->objective.requests_per_second = rps_item->valueint;
        } else {
            config->objective.requests_per_second = -1; // Use -1 to signify "max speed"
        }
        config->objective.requests_per_connection = get_int_from_json(objective_json, "requests_per_connection");
    }

    // Parse network config
    cJSON *network_json = cJSON_GetObjectItemCaseSensitive(json, "network");
    if (network_json) {
        cJSON *l2_json = cJSON_GetObjectItemCaseSensitive(network_json, "l2");
        if (l2_json) {
            config->l2.mac_address = get_string_from_json(l2_json, "mac_address");
        }

        cJSON *l3_json = cJSON_GetObjectItemCaseSensitive(network_json, "l3");
        if (l3_json) {
            config->l3.src_ip_start = get_string_from_json(l3_json, "src_ip_start");
            config->l3.src_ip_end = get_string_from_json(l3_json, "src_ip_end");
            config->l3.dst_ip_start = get_string_from_json(l3_json, "dst_ip_start");
            config->l3.dst_ip_end = get_string_from_json(l3_json, "dst_ip_end");
        }

        cJSON *l4_json = cJSON_GetObjectItemCaseSensitive(network_json, "l4");
        if (l4_json) {
            config->l4.protocol = get_string_from_json(l4_json, "protocol");
            config->l4.src_port_start = get_int_from_json(l4_json, "src_port_start");
            config->l4.src_port_end = get_int_from_json(l4_json, "src_port_end");
            config->l4.dst_port_start = get_int_from_json(l4_json, "dst_port_start");
            config->l4.dst_port_end = get_int_from_json(l4_json, "dst_port_end");
        }
    }

    // Parse dpdk config
    cJSON *dpdk_json = cJSON_GetObjectItemCaseSensitive(json, "dpdk");
    if (dpdk_json) {
        config->dpdk.iface = get_string_from_json(dpdk_json, "iface");
        config->dpdk.args = get_string_from_json(dpdk_json, "args");
    }

    // Parse client payload
    cJSON *client_payload_json = cJSON_GetObjectItemCaseSensitive(json, "client_payload");
    if (client_payload_json) {
        config->client_payload.data = get_string_from_json(client_payload_json, "data");
        config->client_payload.size = get_int_from_json(client_payload_json, "size");
    }

    // Parse server response
    cJSON *server_response_json = cJSON_GetObjectItemCaseSensitive(json, "server_response");
    if (server_response_json) {
        config->server_response.data = get_string_from_json(server_response_json, "data");
        config->server_response.size = get_int_from_json(server_response_json, "size");
    }

    // Parse http config
    cJSON *http_config_json = cJSON_GetObjectItemCaseSensitive(json, "http_config");
    if (http_config_json) {
        config->http_config.client_request_path = get_string_from_json(http_config_json, "client_request_path");
        config->http_config.response_size_hello = get_int_from_json(http_config_json, "response_size_hello");
        config->http_config.response_size_another = get_int_from_json(http_config_json, "response_size_another");
        config->http_config.response_size_default = get_int_from_json(http_config_json, "response_size_default");
        config->http_config.use_https = get_int_from_json(http_config_json, "use_https");
        config->http_config.cert_path = get_string_from_json(http_config_json, "cert_path");
        config->http_config.key_path = get_string_from_json(http_config_json, "key_path");
    }

    config->use_https = config->http_config.use_https;
    config->cert_path = config->http_config.cert_path;
    config->key_path = config->http_config.key_path;

    // Parse interface config
    cJSON *interface_json = cJSON_GetObjectItemCaseSensitive(json, "interface");
    if (interface_json) {
        config->interface.mtu = get_int_from_json(interface_json, "mtu");
    }

    cJSON_Delete(json);
    return 0;
}

void free_config(perf_config_t *config) {
    if (config) {
        free(config->objective.type);
        free(config->l2.mac_address);
        free(config->l3.src_ip_start);
        free(config->l3.src_ip_end);
        free(config->l3.dst_ip_start);
        free(config->l3.dst_ip_end);
        free(config->l4.protocol);
        free(config->dpdk.iface);
        free(config->dpdk.args);
        free(config->client_payload.data);
        free(config->server_response.data);
        free(config->http_config.client_request_path);
        free(config->http_config.cert_path);
        free(config->http_config.key_path);
    }
}
