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
        config->objective.requests_per_connection = get_int_from_json(objective_json, "requests_per_connection");
    }

    // Parse network config
    cJSON *network_json = cJSON_GetObjectItemCaseSensitive(json, "network");
    if (network_json) {
        config->network.mac_address = get_string_from_json(network_json, "mac_address");
        config->network.src_ip_start = get_string_from_json(network_json, "src_ip_start");
        config->network.src_ip_end = get_string_from_json(network_json, "src_ip_end");
        config->network.dst_ip_start = get_string_from_json(network_json, "dst_ip_start");
        config->network.dst_ip_end = get_string_from_json(network_json, "dst_ip_end");
        config->network.protocol = get_string_from_json(network_json, "protocol");
        config->network.src_port_start = get_int_from_json(network_json, "src_port_start");
        config->network.src_port_end = get_int_from_json(network_json, "src_port_end");
        config->network.dst_port_start = get_int_from_json(network_json, "dst_port_start");
        config->network.dst_port_end = get_int_from_json(network_json, "dst_port_end");
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
    }

    cJSON_Delete(json);
    return 0;
}

void free_config(perf_config_t *config) {
    if (config) {
        free(config->objective.type);
        free(config->network.mac_address);
        free(config->network.src_ip_start);
        free(config->network.src_ip_end);
        free(config->network.dst_ip_start);
        free(config->network.dst_ip_end);
        free(config->network.protocol);
        free(config->client_payload.data);
        free(config->server_response.data);
        free(config->http_config.client_request_path);
    }
}
