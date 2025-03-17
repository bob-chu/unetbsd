#include <sys/param.h>
#include <sys/mbuf.h>
#include <sys/kernel.h>
#include <net/if.h>
#include <net/pktqueue.h>
#include <netinet/in.h>

// 定义空的 pktqueue 结构体（仅占位）
struct pktqueue {
    void *dummy;
};

// 替代 pktq_create，直接返回 NULL，不分配实际队列
pktqueue_t *
pktq_create(int limit, void (*softint)(void *), void *arg)
{
    return NULL; // 不需要队列，直接返回空指针
}

// 替代 pktq_enqueue，直接调用下一个处理函数
int
pktq_enqueue(pktqueue_t *pq, struct mbuf *m, const int ipktq)
{
    // 直接将数据包交给接口输入处理
    if (m != NULL && m->m_pkthdr.rcvif != NULL) {
        if_input(m->m_pkthdr.rcvif, m);
        return 0; // 成功
    }
    m_freem(m); // 如果无法处理，释放内存
    return ENOBUFS; // 表示失败
}

// 替代 pktq_dequeue，直接返回 NULL（无队列）
struct mbuf *
pktq_dequeue(pktqueue_t *pq)
{
    return NULL; // 无队列，直接返回空
}

// 替代 pktq_ifdetach，无操作
void
pktq_ifdetach(struct ifnet *ifp)
{
    // 无需处理队列，直接返回
}

// 替代 pktq_rps_hash，直接返回固定值
u_int
pktq_rps_hash(const struct mbuf *m)
{
    return 0; // 返回固定值，禁用 RPS
}

// 替代 pktq_rps_hash_default，无操作
void
pktq_rps_hash_default(void)
{
    // 空实现
}

// 替代 pktq_sysctl_setup，无操作
void
pktq_sysctl_setup(void)
{
    // 空实现
}

// 替代 sysctl_pktq_rps_hash_handler，无操作
int
sysctl_pktq_rps_hash_handler(SYSCTLFN_ARGS)
{
    return 0; // 空实现，返回成功
}
