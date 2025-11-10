#include <sys/param.h>
#include <sys/systm.h>
#include <sys/mbuf.h>
#include <sys/malloc.h>
#include <sys/kernel.h>

#include "u_pktqueue.h"

#define PKTQUEUE_SIZE 1024

struct pktqueue {
	struct mbuf *pq_mem[PKTQUEUE_SIZE];
	int pq_head;
	int pq_tail;
	void (*pq_intrh)(void *);
	void *pq_sc;
};

struct pktqueue *
pktq_create(size_t maxlen, void (*intrh)(void *), void *sc)
{
	struct pktqueue *pq;

	pq = malloc(sizeof(*pq), M_DEVBUF, M_WAITOK | M_ZERO);
	pq->pq_intrh = intrh;
	pq->pq_sc = sc;

	return pq;
}

void
pktq_destroy(struct pktqueue *pq)
{
	free(pq, M_DEVBUF);
}

bool
pktq_enqueue(struct pktqueue *pq, struct mbuf *m, const u_int hash)
{
	int next_tail;

	next_tail = (pq->pq_tail + 1) % PKTQUEUE_SIZE;
	if (next_tail == pq->pq_head) {
		m_freem(m);
		return false;
	}

	pq->pq_mem[pq->pq_tail] = m;
	pq->pq_tail = next_tail;

	pq->pq_intrh(pq->pq_sc);

	return true;
}

struct mbuf *
pktq_dequeue(struct pktqueue *pq)
{
	struct mbuf *m;

	if (pq->pq_head == pq->pq_tail) {
		return NULL;
	}

	m = pq->pq_mem[pq->pq_head];
	pq->pq_head = (pq->pq_head + 1) % PKTQUEUE_SIZE;

	return m;
}