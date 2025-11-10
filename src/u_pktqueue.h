#ifndef _U_PKTQUEUE_H_
#define _U_PKTQUEUE_H_

#include <sys/mbuf.h>

struct pktqueue;

struct pktqueue *pktq_create(size_t maxlen, void (*intrh)(void *), void *sc);
void pktq_destroy(struct pktqueue *pq);
bool pktq_enqueue(struct pktqueue *pq, struct mbuf *m, const u_int hash);
struct mbuf *pktq_dequeue(struct pktqueue *pq);

#endif /* _U_PKTQUEUE_H_ */
