#include "../include/u_cmdqueue.h"
#include <string.h>

void cmd_queue_init(cmd_queue_t *q) {
    memset(q, 0, sizeof(*q));
#ifndef _KERNEL
    pthread_mutex_init(&q->lock, NULL);
    sem_init(&q->avail, 0, 0);
#else
    // Kernel mode initialization - to be implemented with kernel synchronization
#endif
}

int cmd_queue_enqueue(cmd_queue_t *q, cmd_t *cmd) {
#ifndef _KERNEL
    pthread_mutex_lock(&q->lock);
    
    int next = (q->tail + 1) % CMD_QUEUE_SIZE;
    if (next == q->head) {
        pthread_mutex_unlock(&q->lock);
        return -1;  // Queue full
    }
    
    q->commands[q->tail] = cmd;
    q->tail = next;
    
    pthread_mutex_unlock(&q->lock);
    sem_post(&q->avail);
#else
    // Kernel mode enqueue - to be implemented
#endif
    return 0;
}

cmd_t *cmd_queue_dequeue(cmd_queue_t *q) {
#ifndef _KERNEL
    sem_wait(&q->avail);
    
    pthread_mutex_lock(&q->lock);
    
    if (q->head == q->tail) {
        pthread_mutex_unlock(&q->lock);
        return NULL;
    }
    
    cmd_t *cmd = q->commands[q->head];
    q->head = (q->head + 1) % CMD_QUEUE_SIZE;
    
    pthread_mutex_unlock(&q->lock);
    return cmd;
#else
    // Kernel mode dequeue - to be implemented
    return NULL;
#endif
}

void cmd_queue_wait_for_completion(cmd_t *cmd) {
#ifndef _KERNEL
    sem_wait(&cmd->completion);
#else
    // Kernel mode wait - to be implemented
#endif
}
