#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "u_tcp_stat.h"
#include "init.h"

int main() {
    printf("Initializing NetBSD stack...\n");
    
    netbsd_init();
    
    printf("Retrieving TCP statistics...\n");
    
    uint64_t stats[UNETBSD_TCP_NSTATS];
    size_t len = UNETBSD_TCP_NSTATS;
    
    int ret = unetbsd_get_tcp_stats(stats, &len);
    if (ret != 0) {
        fprintf(stderr, "Failed to get TCP stats: %d\n", ret);
        return 1;
    }
    
    printf("\n--- NetBSD TCP Statistics (%zu counters) ---\n", len);
    int found_non_zero = 0;
    for (int i = 0; i < (int)len; i++) {
        const char *name = unetbsd_get_tcp_stat_name(i);
        if (name) {
            printf("%-50s: %lu\n", name, stats[i]);
            if (stats[i] > 0) found_non_zero = 1;
        }
    }
    
    if (!found_non_zero) {
        printf("\nNote: All counters are zero (stack newly initialized).\n");
    }
    printf("-------------------------------------------\n");
    
    return 0;
}
