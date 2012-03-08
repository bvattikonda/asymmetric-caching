#include "as_base_station.h"

unsigned char *new_packet = NULL;
// Rabin array of powers for all byte values
long long powers[256];
// global data structures
map<uint64_t, float> regular_cache; //indexes the timestamp of each hash
map<uint64_t, float> feedback_cache;

FILE *logfile = fopen("as_base_station.log", "w");
uint8_t system_loglevel = LOG_DEBUG;

/********************* cache management ***************************/

/********************* upstream code *****************************/
int recvFeedback(struct nfq_data* buf, int *size, int flag)
{
    // read the IP options field, if set for asymmetric caching, proceed, else return this packet
    // get to the TCP payload
    // parse the packet based on 2B shim headers, or just read out HASH_LEN chunks
    // set the payload to empty
    // recompute TCP checksum(if changed by mobile) and IP checksum
    // return the simple packet upstream
    return 0;
}

uint16_t pack_hash_value(unsigned char *packet, uint32_t left, uint32_t right) {
    uint16_t bytes_packed = 0;
    pack_buffer(uint16_t, packet, bytes_packed, htons(HASH_HDR | HASH_LEN));
    bytes_packed += 2;

    /* copy the hash into the new packet */
    pack_buffer(uint32_t, packet, bytes_packed, htonl(left));
    bytes_packed += 4;
    pack_buffer(uint32_t, packet, bytes_packed, htonl(right));
    bytes_packed += 4;
    return bytes_packed;
}

/********************* downstream code *****************************/
int dedup(struct nfq_data* buf, int *size, int flag) {
    struct timeval time_now;
    gettimeofday(&time_now, NULL);
    double tstamp = time_now.tv_sec + 0.000001*time_now.tv_usec;
    printf("Hello world!\n");
    int i=0, j=0;
    // extract the headers of the packet
    struct nfqnl_msg_packet_hdr *ph;
    ph = nfq_get_msg_packet_hdr(buf);
    int id = ntohl(ph->packet_id);

    u_char *pkt_ptr;
    int buf_len = nfq_get_payload(buf, (char **)&pkt_ptr); //get the packet data.
    
    struct ip *ip_hdr = (struct ip *)pkt_ptr;
    uint32_t size_ip = 4*ntohl(ip_hdr->ip_hl);

    if (size_ip < 20) 
        printf("  * Invalid IP header length: %u bytes\n", size_ip);
        return id;

    // get to the IP payload
    struct tcphdr *tcp_hdr;
    if (ip_hdr->ip_p == IP_PROTO_TCP)
    {
        pkt_ptr += size_ip;
        tcp_hdr = (struct tcphdr*)pkt_ptr; //data_udp is same as data_ip
    }
    else
        return id;

    // get to the TCP payload
    int data_offset = 4 * ntohs(tcp_hdr->doff);
    pkt_ptr += data_offset;
    u_char* payload = (u_char*)pkt_ptr;

    uint16_t payload_len = ntohs(ip_hdr->ip_len) - data_offset; // length in IP header minus the header length of TCP 
    printlog(logfile, system_loglevel, LOG_DEBUG, "Payload length: %d\n", payload_len);

    //if payload length is <= MIN_CHUNK_LEN, just pass the packet as it is
    if(payload_len <= MIN_CHUNK_LEN)
        return id;

    // if payload length > HASH_LEN
    // get markers for rabin fingerprinting
    uint16_t store_marks[MAX_MARKS];
    memset(new_packet, 0, sizeof(unsigned char *) * MAX_PACKET_LEN);
    bool dedup_flag = false;
    uint16_t num_chunks = rabinFingerprints(store_marks, payload, payload_len, powers,
            MIN_CHUNK_LEN);
    uint32_t left = 0, right = 0;
    // b=0, c=0, hashlittle2("Four score and seven years ago", 30, &c, &b);
    // returns the final value in c and b
    // to generate a 64 bit number do something like "*pc + (((uint64_t)*pb)<<32)".

    uint16_t chunk_length = 0, hash_copy_index = 0, last_marker = 0,
             packed_upto = 0;
    for(i=0; i< num_chunks;i++) {
        chunk_length = store_marks[i] - last_marker; 
        left = 0, right = 0;
        hashlittle2((void*)(payload + last_marker), chunk_length, &right, &left);
        printlog(logfile, system_loglevel, LOG_DEBUG, "Hashing chunk\
                from %d to %d\n", last_marker, store_marks[i]);
        uint64_t hash_value = right + (((uint64_t)left)<<32);
        if(regular_cache.find(hash_value) != regular_cache.end()) {
            packed_upto += pack_hash_value(new_packet + packed_upto, left, right);
            dedup_flag = true;
            printlog(logfile, system_loglevel, LOG_DEBUG, "Normal hit\
                    %.llx\n", (unsigned long long)hash_value);
            /* update length in the header */
        } else if (feedback_cache.find(hash_value) !=
                feedback_cache.end()) {
            packed_upto += pack_hash_value(new_packet + packed_upto, left, right);
            dedup_flag = true;
            printlog(logfile, system_loglevel, LOG_DEBUG, "Advert hit\
                    %.llx\n", (unsigned long long)hash_value);
            // remove from this cache
            feedback_cache.erase(hash_value);
            // insert in normal cache
        } else {
            // fresh chunk
            pack_buffer(uint16_t, new_packet, packed_upto, htons(chunk_length));
            packed_upto += 2;
            memcpy(new_packet + packed_upto, payload + last_marker, chunk_length);
            packed_upto += chunk_length;
        }
        // add this chunk to the regular cache
        regular_cache[hash_value] = tstamp;
        last_marker = store_marks[i];
    }

    /* if no text has been modified, send the packet as it is but set the
     * appropriate value in the options field to indicate that this packet has
     * been cached at the base-station if packet has been modified, set the
     * appropriate value in the IP options
     */
    if(packed_upto >= payload_len) {
        packed_upto = payload_len;
        ip_hdr->ip_p = DEDUP_CLEAR;
    } else if(dedup_flag){
        memcpy(payload, new_packet, packed_upto);
        ip_hdr->ip_p = DEDUP_MIXED;
    } else {
        printlog(logfile, system_loglevel, LOG_CRITICAL, "ERROR: no\
                dedup but new packet smaller than original\n");
        packed_upto = payload_len;
        ip_hdr->ip_p = DEDUP_CLEAR;
    }

    /* set IP options so that mobile knows that it needs to generate feedback
     * for this compute the IP checksum
    */

    ip_hdr->ip_len = htons(packed_upto);
    ip_hdr->ip_sum = ip_header_checksum((uint16_t *)ip_hdr, sizeof(struct ip));
    return id; 
}

static int cbDown(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *payload)
{
    char *send_data;
    int i,newSize;
    u_int32_t id = dedup(nfa, &newSize,1);
    i = nfq_get_payload(nfa,&send_data);
    return nfq_set_verdict(qh, id, NF_ACCEPT, newSize, (unsigned char *)send_data);
}

void createQueue(int queue_num, int (*callback)(struct nfq_q_handle *, struct nfgenmsg *, struct nfq_data *, void *))
{
    // get code from nfqnl_test.c
    return;
}

void downstreamDedup()
{
    // create the global data structures
    // create an NF queue to get packets, tie this to queue 0
    initializeRabin(powers);
    createQueue(0, &cbDown);
    return;
}

/************************* main *******************************/
int main() {
    new_packet = (unsigned char *)malloc(MAX_PACKET_LEN);
    if(new_packet == NULL) {
        printf("Malloc failed\n");
        exit(EXIT_FAILURE);
    }
    downstreamDedup();
    // start the downstream code, later move to a thread
    // start the upstream code, later move to a thread
    return 0;
}
