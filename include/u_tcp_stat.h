#ifndef U_TCP_STAT_H
#define U_TCP_STAT_H

#include <sys/types.h>
#include <stdint.h>

#define UNETBSD_TCP_NSTATS 76

#ifdef __cplusplus
extern "C" {
#endif

const char *unetbsd_get_tcp_stat_name(int index);
int unetbsd_get_tcp_stats(uint64_t *stats, size_t *len);

#ifdef __cplusplus
}
#endif

#endif /* U_TCP_STAT_H */
