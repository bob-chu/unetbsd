#include "kernel_compat.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>


void *stdlib_malloc(size_t size) {
    return malloc(size); // 调用标准库的 malloc
}

void stdlib_free(void *ptr) {
    free(ptr);        // 调用标准库的 free
}


int user_printf(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    int ret = vprintf(fmt, args); // 使用 vprintf
    va_end(args);
    return ret;
}

// **  可能需要添加其他 overwrite 函数的实现  **
