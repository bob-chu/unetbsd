// logger.h
#ifndef _LOGGER_H_
#define _LOGGER_H_

#include <stdio.h>
#include <stdarg.h>
#include <time.h>
#include <string.h>
#include <pthread.h>

// Log levels
typedef enum {
    LOG_LEVEL_TRACE = 0,
    LOG_LEVEL_DEBUG,
    LOG_LEVEL_INFO,
    LOG_LEVEL_WARN,
    LOG_LEVEL_ERROR,
    LOG_LEVEL_FATAL
} log_level_t;

// Log colors
#define LOG_COLOR_BLACK   "\x1b[30m"
#define LOG_COLOR_RED     "\x1b[31m"
#define LOG_COLOR_GREEN   "\x1b[32m"
#define LOG_COLOR_YELLOW  "\x1b[33m"
#define LOG_COLOR_BLUE    "\x1b[34m"
#define LOG_COLOR_MAGENTA "\x1b[35m"
#define LOG_COLOR_CYAN    "\x1b[36m"
#define LOG_COLOR_RESET   "\x1b[0m"

// Configuration structure
typedef struct {
    FILE* output_file;
    log_level_t min_level;
    int use_colors;
    pthread_mutex_t lock;
    const char* time_format;
} logger_config_t;

// Initialize logger with default settings
void logger_init(void);

// Configure logger
void logger_set_level(log_level_t level);
void logger_set_output(FILE* file);
void logger_enable_colors(int enable);
void logger_set_time_format(const char* format);

// Main logging function
void logger_log(const char* file, int line, log_level_t level, const char* fmt, ...);

// Convenience macros
#define LOG_TRACE(...) logger_log(__FILE__, __LINE__, LOG_LEVEL_TRACE, __VA_ARGS__)
#define LOG_DEBUG(...) logger_log(__FILE__, __LINE__, LOG_LEVEL_DEBUG, __VA_ARGS__)
#define LOG_INFO(...)  logger_log(__FILE__, __LINE__, LOG_LEVEL_INFO,  __VA_ARGS__)
#define LOG_WARN(...)  logger_log(__FILE__, __LINE__, LOG_LEVEL_WARN,  __VA_ARGS__)
#define LOG_ERROR(...) logger_log(__FILE__, __LINE__, LOG_LEVEL_ERROR, __VA_ARGS__)
#define LOG_FATAL(...) logger_log(__FILE__, __LINE__, LOG_LEVEL_FATAL, __VA_ARGS__)

#endif // _LOGGER_H_


