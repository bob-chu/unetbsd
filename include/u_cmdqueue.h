#ifndef U_CMDQUEUE_H
#define U_CMDQUEUE_H

#ifndef _KERNEL
#include <pthread.h>
#include <semaphore.h>
#else
/* In kernel mode, we don't use user-space threading primitives */
typedef struct {
    int dummy;  /* Placeholder for kernel synchronization */
} sem_t;

typedef struct {
    int dummy;  /* Placeholder for kernel mutex */
} pthread_mutex_t;
#endif

typedef enum {
    CMD_SOCKET,
    CMD_BIND,
    CMD_LISTEN,
    CMD_CONNECT,
    CMD_ACCEPT,
    CMD_SEND,
    CMD_RECV,
    CMD_CLOSE,
    CMD_SHUTDOWN
} cmd_type_t;

typedef struct {
    cmd_type_t type;
    int fd;
    void *data;
    size_t data_len;
    int result;
    int error_code;
    sem_t completion;  // Used for synchronous waiting for results
    char completed;    // Flag to indicate completion
} cmd_t;

#define CMD_QUEUE_SIZE 1024

typedef struct {
    cmd_t *commands[CMD_QUEUE_SIZE];
    int head;
    int tail;
    pthread_mutex_t lock;
    sem_t avail;  // Available commands count
} cmd_queue_t;

// Command queue operations
void cmd_queue_init(cmd_queue_t *q);
int cmd_queue_enqueue(cmd_queue_t *q, cmd_t *cmd);
cmd_t *cmd_queue_dequeue(cmd_queue_t *q);
void cmd_queue_wait_for_completion(cmd_t *cmd);

#endif // U_CMDQUEUE_H
