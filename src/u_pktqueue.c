#include <sys/param.h>
#include <sys/systm.h>
#include <sys/mbuf.h>
#include <sys/malloc.h>
#include <sys/kernel.h>

#include "u_pktqueue.h"

#define PKTQUEUE_SIZE (1024*2)

struct pktqueue {
	struct mbuf *pq_mem[PKTQUEUE_SIZE];
	int pq_head;
	int pq_tail;
	void (*pq_intrh)(void *);
	void *pq_sc;
	void *pq_sih;
};

static void pktq_dequeue_all(void *arg);

struct pktqueue *
pktq_create(size_t maxlen, void (*intrh)(void *), void *sc)
{
	struct pktqueue *pq;
	void *sih;

	pq = malloc(sizeof(*pq), M_DEVBUF, M_WAITOK | M_ZERO);
	pq->pq_head = 0;
	pq->pq_tail = 0;
	pq->pq_intrh = intrh;
	pq->pq_sc = sc;
	sih = softint_establish(SOFTINT_NET | SOFTINT_MPSAFE, pktq_dequeue_all, pq);
    printf("pkt_queue create, softint establish intrh:%p, sc: %p\n", pq->pq_intrh, pq->pq_sc);
    if (!sih) {
        printf("softint_establish failed. exit\n");
        exit(1);
    }
    pq->pq_sih = sih;
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
		printf("Packet queue full, dropping packet at address %p\n", (void*)m);
		m_freem(m);
		return false;
	}

	pq->pq_mem[pq->pq_tail] = m;
	pq->pq_tail = next_tail;

	/*
	 * Schedule a soft interrupt to be executed later by softint_run().
	 * This prevents recursive stack processing and solves the race 
	 * condition where response packets arrive before current entry 
	 * is inserted into the cache.
	 */
	softint_schedule(pq->pq_sih);

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

/*
 * Dequeue all packets from the queue and trigger the interrupt handler.
 * This function is intended to be called by the soft interrupt mechanism.
 */
static void
pktq_dequeue_all(void *arg)
{
	struct pktqueue *pq = (struct pktqueue *)arg;

    if (pq->pq_intrh) {
        //printf("pkt_queue run; intrh:%p, sc: %p\n", pq->pq_intrh, pq->pq_sc);
        pq->pq_intrh(pq->pq_sc);
    }
}
