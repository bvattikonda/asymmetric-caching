#include <as_common.h>

// macros at the base-station
#define IP_OPT_ORIGINAL 26
#define IP_OPT_MIXED 27
#define MAX_CHUNK_SIZE MTU
#define MAX_PACKET_LEN (MTU + (MTU / (MIN_CHUNK_LEN)))
#define DEBUG 0
