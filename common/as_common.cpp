#include <as_common.h>

uint16_t ip_header_checksum(const uint16_t *addr, register u_int len) { 
    struct ip *ip_hdr = (struct ip *)((unsigned char *)addr);
    ip_hdr->ip_sum = 0;
    int nleft = len; 
    const uint16_t *w = addr; 
    uint16_t answer = 0; 
    int sum = 0; //= csum;

    /* Our algorithm is simple, using a 32 bit accumulator (sum), we add
     * sequential 16 bit words to it, and at the end, fold back all the carry
     * bits from the top 16 bits into the lower 16 bits. */ 

    while (nleft > 1) 
    { 

        sum += *w++; 

        nleft -= 2; 
    } 

    /* add back carry outs from top 16 bits to low 16 bits */ 

    sum = (sum >> 16) + (sum & 0xffff); /* add hi 16 to low 16 */ 
    sum += (sum >> 16); /* add carry */ 
    answer = ~sum;  /* truncate to 16 bits */ 
    return (answer);
}
