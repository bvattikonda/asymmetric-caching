#include <pc_common.h>

// macros at the base-station
#define MAX_CHUNK_SIZE MTU
#define MAX_PACKET_LEN (MTU + (MTU / (MIN_CHUNK_LEN)))
#define DEBUG 0
