#ifndef _UTIL_
#define _UTIL_

#define __STDC_FORMAT_MACROS
#include <inttypes.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <stdint.h>
#include <execinfo.h>
#include <ifaddrs.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <signal.h>
#include <fcntl.h>
#include <assert.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <sys/shm.h>
#include <sys/ioctl.h>
#include <linux/types.h>
#include <net/if.h> 
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <sys/ioctl.h>
#include <sys/uio.h>
#include <unistd.h>
using namespace std;
#include <cstring>
#include <map>
#include <utility>
#include <iostream>

#include "logging.h"

#define pack_buffer(type, buffer, offset, value) *((type *) (buffer + offset)) = (value)
#define unpack_buffer(type, buffer, offset) *((type *) (buffer + offset)) 

#define TRUE 1
#define FALSE 0
#define USECS_PER_SEC 1000000
#define NSECS_PER_SEC 1000000000
#define NSECS_PER_USEC 1000

void ip_from_bytes(uint32_t addr, char *buf, int nbo);

void mac_from_bytes(unsigned char *mac, char *buf);

void dump_data(FILE *logfile, uint8_t thread_loglevel, uint8_t
        loglevel, unsigned char *pg, int len);

void print_mac(unsigned char *mac);
#endif
