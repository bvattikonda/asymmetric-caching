#include "pc_server.h"

unsigned char *new_packet = NULL;
// Rabin array of powers for all byte values
long long powers[256];
// global data structures
map<uint64_t, time_t> regular_cache; //indexes the timestamp of each hash
map<uint64_t, time_t> prefetch_cache;

FILE *logfile = fopen("pc_server.log", "w");
uint8_t system_loglevel = LOG_DEBUG;

uint32_t actual_traffic = 0;
uint32_t dedup_traffic = 0;
uint32_t prefetch_bytes = 0;

/********************* cache management ***************************/

/********************* upstream code *****************************/

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

uint64_t insert_hash(uint16_t chunk_length, uint16_t *packed_upto,
        unsigned char *payload,
        uint16_t last_marker,
        bool *dedup_flag,
        time_t current_timestamp) {
    uint16_t local_packed_upto = (*packed_upto);
    uint32_t left = 0, right = 0;
    hashlittle2((void*)(payload + last_marker), chunk_length, &right, &left);
    printlog(logfile, system_loglevel, LOG_DEBUG, "Hashing chunk"
            " from %d to %d\n", packed_upto, packed_upto +
            chunk_length);
    uint64_t hash_value = right + (((uint64_t)left)<<32);
    uint16_t advance_by = 0;
    if(regular_cache.find(hash_value) != regular_cache.end()) {
        printlog(logfile, system_loglevel, LOG_DEBUG, "Putting regular hash %llx for chunk length  %d\n", hash_value, chunk_length);
        advance_by += pack_hash_value(new_packet + local_packed_upto, left, right);
        *dedup_flag = true;
        printlog(logfile, system_loglevel, LOG_DEBUG, "Normal hit: "
                "%.llx\n", (unsigned long long)hash_value);
    } else if (prefetch_cache.find(hash_value) !=
            prefetch_cache.end()) {
        printlog(logfile, system_loglevel, LOG_DEBUG, "Putting feedback hash %llx for chunk length  %d\n", hash_value, chunk_length);
        advance_by += pack_hash_value(new_packet + local_packed_upto, left, right);
        *dedup_flag = true;
        printlog(logfile, system_loglevel, LOG_DEBUG, "Advert hit\
                %.llx\n", (unsigned long long)hash_value);
        prefetch_cache.erase(hash_value);
    } else {
        /* fresh chunk */
        printlog(logfile, system_loglevel, LOG_DEBUG, "New hash %llx for chunk length  %d\n", hash_value, chunk_length);
        pack_buffer(uint16_t, new_packet, local_packed_upto, htons(chunk_length));
        advance_by += 2;
        local_packed_upto += 2;
        memcpy(new_packet + local_packed_upto, payload + last_marker, chunk_length);
        advance_by += chunk_length;
        local_packed_upto += chunk_length;
        printlog(logfile, system_loglevel, LOG_DEBUG,
                "chunk_length: %d\n", chunk_length);
    }
    /* add this chunk to the regular cache */
    *packed_upto += advance_by;
    return hash_value;
}


/********************* downstream code *****************************/
int dedup(struct nfq_data* buf, int *size) {
    printlog(logfile, system_loglevel, LOG_DEBUG, "***** Packet "
            "received **************\n");
    int i=0;
    // extract the headers of the packet
    struct nfqnl_msg_packet_hdr *ph;
    ph = nfq_get_msg_packet_hdr(buf);
    int id = ntohl(ph->packet_id);

    u_char *pkt_ptr;
    int buf_len = nfq_get_payload(buf, (char **)&pkt_ptr); //get the packet data.
    if(buf_len == -1) {
        printlog(logfile, system_loglevel, LOG_CRITICAL, "Failed to\
                read the packet from netfilter queue\n");
        return 0;
    }
    
    struct ip *ip_hdr = (struct ip *)pkt_ptr;

    uint32_t size_ip = 4 * ip_hdr->ip_hl;

    if (size_ip < 20) {
        printf("* Invalid IP header length: %u bytes\n", size_ip);
        *size = ntohs(ip_hdr->ip_len);
        return id;
    }

    /* get to the IP payload */
    struct tcphdr *tcp_hdr;
    if (ip_hdr->ip_p == IP_PROTO_TCP)
    {
        tcp_hdr = (struct tcphdr*)(pkt_ptr + size_ip); //data_udp is same as data_ip
    } else {
        *size = ntohs(ip_hdr->ip_len);
        return id;
    }

    /* get to the TCP payload */
    int size_tcp = 4 * tcp_hdr->doff;
    u_char* payload = (unsigned char *)(pkt_ptr + size_ip + size_tcp);

    uint16_t payload_len = ntohs(ip_hdr->ip_len) - size_ip - size_tcp; // length in IP header minus the header length of TCP 
    printlog(logfile, system_loglevel, LOG_DEBUG, "Length parameters,"
            "ip_len: %d, size_ip: %d, size_tcp: %d, payload_len:"
            "%d\n", ntohs(ip_hdr->ip_len), size_ip, size_tcp, payload_len);

    /* if payload length is <= MIN_CHUNK_LEN, just pass the packet as
     * it is */
    if(payload_len <= MIN_CHUNK_LEN) {
        *size = ntohs(ip_hdr->ip_len) + size_ip;
        return id;
    }

    // if payload length > MIN_CHUNK_LEN
    actual_traffic += payload_len;
    printlog(logfile, system_loglevel, LOG_CRITICAL, "Actual traffic so far %d\n", actual_traffic);

    // get markers for rabin fingerprinting
    uint16_t store_marks[MAX_MARKS];
    memset(new_packet, 0, sizeof(unsigned char) * MAX_PACKET_LEN);
    bool dedup_flag = false;
    uint16_t num_chunks = rabinFingerprints(store_marks, payload, payload_len, powers,
            MIN_CHUNK_LEN);
    printlog(logfile, system_loglevel, LOG_DEBUG, "num_chunks: %d ", num_chunks);
    for(i = 0; i < num_chunks; i++) {
        printlog(logfile, system_loglevel, LOG_DEBUG, " %d ", store_marks[i]);
    }
    printlog(logfile, system_loglevel, LOG_DEBUG, "\n");

    uint16_t chunk_length = 0, last_marker = 0, packed_upto = 0;
    time_t current_timestamp = time(NULL);
    list<uint64_t> current_hash_list;
    for(i=0; i < num_chunks; i++) {
        chunk_length = store_marks[i] - last_marker; 
        current_hash_list.push_back(insert_hash(chunk_length, &packed_upto,
                payload, last_marker, &dedup_flag, current_timestamp));
        last_marker = store_marks[i];
    }
    uint16_t chunked_upto = 0;
    if(num_chunks == 0) {
        chunked_upto = 0;
    } else {
        chunked_upto = store_marks[num_chunks - 1];
    }
    if(chunked_upto < payload_len - 1) {
        chunk_length = payload_len - chunked_upto;
        current_hash_list.push_back(insert_hash(chunk_length, &packed_upto,
                payload, chunked_upto, &dedup_flag, current_timestamp));
    }

    for(list<uint64_t>::iterator it = current_hash_list.begin(); it !=
        current_hash_list.end(); it++) {
    	//printlog(logfile, system_loglevel, LOG_DEBUG, "Inserting hash %llx\n", it);
        regular_cache[(*it)] = current_timestamp;
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
        printlog(logfile, system_loglevel, LOG_CRITICAL, "ERROR: no"
                "dedup but new packet smaller than original"
                "packed_upto: %d, payload_len: %d\n", packed_upto,
                payload_len);
        packed_upto = payload_len;
        ip_hdr->ip_p = DEDUP_CLEAR;
    }

    /* set IP options so that mobile knows that it needs to generate feedback
     * for this compute the IP checksum
    */

    dedup_traffic += packed_upto;
    printlog(logfile, system_loglevel, LOG_CRITICAL, "Dedup traffic so far %d\n", dedup_traffic);

    ip_hdr->ip_len = htons(size_ip + size_tcp + packed_upto);
    ip_hdr->ip_sum = ip_header_checksum((uint16_t *)ip_hdr, sizeof(struct ip));
    *size = ntohs(ip_hdr->ip_len);
    printlog(logfile, system_loglevel, LOG_DEBUG, "Final length parameters,"
            "ip_len: %d, size: %d\n", ntohs(ip_hdr->ip_len), *size);
    return id; 
}

static int cbDown(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
        struct nfq_data *nfa, void *payload) {
    char *send_data;
    int i, newSize;
    u_int32_t id = dedup(nfa, &newSize);
    printlog(logfile, system_loglevel, LOG_DEBUG, "ID of the packet"
            " to be sent out %u\n", id);
    i = nfq_get_payload(nfa, &send_data);
    return nfq_set_verdict(qh, id, NF_ACCEPT, newSize, (unsigned char *)send_data);
}

int createQueue(struct nfq_handle *h, int queue_num, int
        (*callback)(struct nfq_q_handle *, struct nfgenmsg *, struct nfq_data
            *, void *)) {
    // get code from nfqnl_test.c
    struct nfq_q_handle *qh;
    int fd = 0;
    int rv = 0;

    printf("binding this socket to queue %d\n", queue_num);
    qh = nfq_create_queue(h,  queue_num, callback, NULL);
    if (!qh) {
        fprintf(stderr, "error during nfq_create_queue()\n");
        exit(1);
    }

    printf("setting copy_packet mode Boo Yeah!!\n");
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        fprintf(stderr, "can't set packet_copy mode\n");
        exit(1);
    }
    printf("Packet Mode Set\n");
    fd = nfq_fd(h);

    if(nfq_set_queue_maxlen(qh, 100) < 0 )
    {
        fprintf(stderr,"---\nCannot set queue max len \n---");
    }

    return fd;
}

struct nfq_handle *get_handle() {
    struct nfq_handle *h;

    printf("opening library handle\n");
    h = nfq_open();
    if (!h) {
        fprintf(stderr, "error during nfq_open()\n");
        exit(1);
    }

    printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
    if (nfq_unbind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_unbind_pf()\n");
        exit(1);
    }

    printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
    if (nfq_bind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_bind_pf()\n");
        exit(1);
    }

    return h;
}

/************************* main *******************************/
int main() {
    new_packet = (unsigned char *)malloc(MAX_PACKET_LEN);
    if(new_packet == NULL) {
        printf("Malloc failed\n");
        exit(EXIT_FAILURE);
    }

    struct nfq_handle *h = get_handle();
    fd_set rfds;

    // start the downstream code, later move to a thread
    initializeRabin(powers);
    int max_fd = 0;
    int down_fd = createQueue(h, DOWN_BASE_STATION_QUEUE, &cbDown);
    if(down_fd > max_fd)
        max_fd = down_fd;
        
    int n = 0, rv = 0;
    char buf[4096] __attribute__ ((aligned));
    while(true) {
        FD_ZERO(&rfds);
        FD_SET(down_fd, &rfds);
        //FD_SET(up_fd, &rfds);
        n = select(max_fd + 1, &rfds, NULL, NULL, NULL);
        if(n == -1) {
            printlog(logfile, system_loglevel, LOG_CRITICAL, 
                    "Select returned error: %s\n", strerror(errno));
        } 
        if(FD_ISSET(down_fd, &rfds)) {
            rv = recv(down_fd, buf, sizeof(buf), 0);
            if(rv < 0) {
                printlog(logfile, system_loglevel, LOG_CRITICAL, 
                        "recv call failed: %s\n", strerror(errno));
            } else {
                nfq_handle_packet(h, buf, rv);
            }
        } 
    }

    nfnl_rcvbufsiz(nfq_nfnlh(h), 2050 * 4096);
    // start the upstream code, later move to a thread
    return 0;
}
