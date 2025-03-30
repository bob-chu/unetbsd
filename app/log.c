// logger.c
#include "logger.h"

static logger_config_t g_config = {
    .output_file = NULL,
    .min_level = LOG_LEVEL_INFO,
    .use_colors = 1,
    .time_format = "%Y-%m-%d %H:%M:%S"
};

static const char* level_strings[] = {
    "TRACE", "DEBUG", "INFO", "WARN", "ERROR", "FATAL"
};

static const char* level_colors[] = {
    LOG_COLOR_BLUE,    // TRACE
    LOG_COLOR_CYAN,    // DEBUG
    LOG_COLOR_GREEN,   // INFO
    LOG_COLOR_YELLOW,  // WARN
    LOG_COLOR_RED,     // ERROR
    LOG_COLOR_MAGENTA // FATAL
};

void logger_init(void) {
    g_config.output_file = stdout;
    pthread_mutex_init(&g_config.lock, NULL);
}

void logger_set_level(log_level_t level) {
    g_config.min_level = level;
}

void logger_set_output(FILE* file) {
    g_config.output_file = file ? file : stderr;
}

void logger_enable_colors(int enable) {
    g_config.use_colors = enable;
}

void logger_set_time_format(const char* format) {
    g_config.time_format = format ? format : "%Y-%m-%d %H:%M:%S";
}

void logger_log(const char* file, int line, log_level_t level, const char* fmt, ...) {
    if (level < g_config.min_level) return;

    pthread_mutex_lock(&g_config.lock);
    // Get current time
#if 0
    time_t t = time(NULL);
    struct tm* lt = localtime(&t);
    char time_str[32];
    strftime(time_str, sizeof(time_str), g_config.time_format, lt);
#endif

    // Get filename without path
    const char* filename = strrchr(file, '/');
    filename = filename ? filename + 1 : file;

    // Print log level with color if enabled
    if (g_config.use_colors) {
        fprintf(g_config.output_file, "%s", level_colors[level]);
    }
#if 0
    // Print log header
    fprintf(g_config.output_file, "[%s] [%s] [%s:%d] ", 
            time_str, level_strings[level], filename, line);
#endif
    // Print actual log message
    va_list args;
    va_start(args, fmt);
    vfprintf(g_config.output_file, fmt, args);
    va_end(args);

    // Reset color and add newline
    if (g_config.use_colors) {
        fprintf(g_config.output_file, LOG_COLOR_RESET);
    }
    fprintf(g_config.output_file, "\n");
    fflush(g_config.output_file);

    pthread_mutex_unlock(&g_config.lock);
}
