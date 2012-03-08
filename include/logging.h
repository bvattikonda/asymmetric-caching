/* See the DRL-LICENSE file for this file's software license. */

#ifndef _LOGGING_H_
#define _LOGGING_H_

#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <sys/time.h>
#include <string.h>
#include <time.h>

#define LOG_CRITICAL    (3)
#define LOG_WARN        (2)
#define LOG_DEBUG       (1)

inline void flushlog(FILE *logfile) {
    fflush(logfile);
}

/**
 * Logging function.  Takes format and arguments similar to printf.
 */
inline void printlog(FILE *logfile, uint8_t loglevel, const uint8_t level, const char *format, ...)
{
    if (loglevel <= level) {
        va_list args;

        va_start(args, format);
        vfprintf(logfile, format, args);
        va_end(args);
    }

    if(loglevel == LOG_DEBUG)
        flushlog(logfile);
}

/**
 * Similar to the function above but also prints time along wtih the log message
 */
inline void printlogwithtime(FILE *logfile, uint8_t loglevel, const uint8_t level, const char *format, ...) {
    if (loglevel <= level) {
        va_list args;
        struct timespec tp;
        memset(&tp, 0, sizeof(struct timespec));
        clock_gettime(CLOCK_MONOTONIC, &tp);

        va_start(args, format);
        fprintf(logfile, "%ld.%09ld ", tp.tv_sec, tp.tv_nsec);
        vfprintf(logfile, format, args);
        va_end(args);
    }

    if(loglevel == LOG_DEBUG)
        flushlog(logfile);
}
#endif  /* _LOGGING_H_ */
