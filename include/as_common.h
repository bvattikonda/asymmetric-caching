#ifndef _AS_COMMON_
#define _AS_COMMON_
#include <iostream>
#include <map>
#include <set>
#include <list>
#include <cmatrix>
#include <logging.h>
#include <util.h>
extern "C" {
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
}
#include <rabin.h>
#include <lookup3.h>

#define DOWN_BASE_STATION_QUEUE 0
#define UP_BASE_STATION_QUEUE 1

#define DOWN_MOBILE_QUEUE 2
#define UP_MOBILE_QUEUE 3

#define ETHER_TYPE_IP (0x0800)
#define IP_PROTO_TCP (6)
#define IP_PROTO_UDP (17)
#define MTU 1460
#define TCP 6
#define HASH_LEN  8
#define MIN_CHUNK_LEN (2 * HASH_LEN)
#define MAX_MARKS (MTU / MIN_CHUNK_LEN)// cannot have more markers than the MTU

#define HASH_HDR 0x8000

#define DEDUP_CLEAR 200
#define DEDUP_MIXED 201
#define ADVERT_PROT 202

using namespace std;
using namespace techsoft;

uint16_t ip_header_checksum(const uint16_t *addr, register u_int len);
#endif
