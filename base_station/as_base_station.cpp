#include "as_base_station.h"

unsigned char *new_packet = NULL;
// Rabin array of powers for all byte values
long long powers[256];
// global data structures
map<uint64_t, time_t> regular_cache; //indexes the timestamp of each hash
map<uint64_t, time_t> feedback_cache;

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

    dump_data(logfile, system_loglevel, LOG_DEBUG, (unsigned char *)
                pkt_ptr, 60);

    /* if payload length is <= MIN_CHUNK_LEN, just pass the packet as
     * it is */
    if(payload_len <= MIN_CHUNK_LEN) {
        *size = ntohs(ip_hdr->ip_len) + size_ip;
        return id;
    }

    // if payload length > HASH_LEN
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

    uint32_t left = 0, right = 0;

    uint16_t chunk_length = 0, last_marker = 0, packed_upto = 0;
    time_t current_timestamp = time(NULL);
    for(i=0; i < num_chunks; i++) {
        chunk_length = store_marks[i] - last_marker; 
        left = 0, right = 0;
        hashlittle2((void*)(payload + last_marker), chunk_length, &right, &left);
        printlog(logfile, system_loglevel, LOG_DEBUG, "Hashing chunk"
                " from %d to %d\n", last_marker, store_marks[i]);
        uint64_t hash_value = right + (((uint64_t)left)<<32);
        if(regular_cache.find(hash_value) != regular_cache.end()) {
            printlog(logfile, system_loglevel, LOG_DEBUG, "Putting regular hash %llx for chunk length  %d\n", hash_value, chunk_length);
            packed_upto += pack_hash_value(new_packet + packed_upto, left, right);
            dedup_flag = true;
            printlog(logfile, system_loglevel, LOG_DEBUG, "Normal hit: "
                    "%.llx\n", (unsigned long long)hash_value);
            /* update length in the header */
        } else if (feedback_cache.find(hash_value) !=
                feedback_cache.end()) {
            printlog(logfile, system_loglevel, LOG_DEBUG, "Putting feedback hash %llx for chunk length  %d\n", hash_value, chunk_length);
            packed_upto += pack_hash_value(new_packet + packed_upto, left, right);
            dedup_flag = true;
            printlog(logfile, system_loglevel, LOG_DEBUG, "Advert hit\
                    %.llx\n", (unsigned long long)hash_value);
            // remove from this cache
            feedback_cache.erase(hash_value);
            // insert in normal cache
        } else {
            /* fresh chunk */
            printlog(logfile, system_loglevel, LOG_DEBUG, "New hash %llx for chunk length  %d\n", hash_value, chunk_length);
            pack_buffer(uint16_t, new_packet, packed_upto, htons(chunk_length));
            packed_upto += 2;
            memcpy(new_packet + packed_upto, payload + last_marker, chunk_length);
            packed_upto += chunk_length;
            printlog(logfile, system_loglevel, LOG_DEBUG,
                    "chunk_length: %d\n", chunk_length);
        }
        /* add this chunk to the regular cache */
        regular_cache[hash_value] = current_timestamp;
        last_marker = store_marks[i];
    }
    uint16_t chunked_upto = 0;
    if(num_chunks == 0) {
        chunked_upto = 0;
    } else {
        chunked_upto = store_marks[num_chunks - 1];
    }
    if(chunked_upto < payload_len - 1) {
        pack_buffer(uint16_t, new_packet, packed_upto, htons(payload_len -
                    chunked_upto));
        packed_upto += 2;
        memcpy(new_packet + packed_upto, payload +
                chunked_upto, payload_len - chunked_upto);
        packed_upto += payload_len - chunked_upto;
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

    ip_hdr->ip_len = htons(size_ip + size_tcp + packed_upto);
    ip_hdr->ip_sum = ip_header_checksum((uint16_t *)ip_hdr, sizeof(struct ip));
    *size = ntohs(ip_hdr->ip_len);
    printlog(logfile, system_loglevel, LOG_DEBUG, "Final length parameters,"
            "ip_len: %d, size: %d\n", ntohs(ip_hdr->ip_len), *size);
    dump_data(logfile, system_loglevel, LOG_DEBUG, (unsigned char
                *)pkt_ptr, 60);
    return id; 
}

static int cbDown(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
        struct nfq_data *nfa, void *payload) {
    char *send_data;
    int i, newSize;
    u_int32_t id = dedup(nfa, &newSize,1);
    printlog(logfile, system_loglevel, LOG_DEBUG, "ID of the packet"
            "to be sent out %u\n", id);
    i = nfq_get_payload(nfa, &send_data);
    return nfq_set_verdict(qh, id, NF_ACCEPT, newSize, (unsigned char *)send_data);
}

void createQueue(int queue_num, int (*callback)(struct nfq_q_handle *,
            struct nfgenmsg *, struct nfq_data *, void *)) {
    // get code from nfqnl_test.c
    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    int fd = 0;
    int rv = 0;
    char buf[4096] __attribute__ ((aligned));

    printf("opening library handle\n");
    h = nfq_open();
    if (!h) {
        fprintf(stderr, "error during nfq_open()\n");
        exit(1);
    }

    printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
    if (nfq_unbind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_unbind_pf()\n");
        //exit(1);
    }

    printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
    if (nfq_bind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_bind_pf()\n");
        exit(1);
    }

    printf("binding this socket to queue '0'\n");
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

    nfnl_rcvbufsiz(nfq_nfnlh(h), 1024 * 4096);

    for (;;) 
    {
        if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) 
        {
            nfq_handle_packet(h, buf, rv);
            continue;
        }
        /* if your application is too slow to digest the packets that
         * are sent from kernel-space, the socket buffer that we use
         * to enqueue packets may fill up returning ENOBUFS. Depending
         * on your application, this error may be ignored. Please, see
         * the doxygen documentation of this library on how to improve
         * this situation.
         */
        if (rv < 0 && errno == ENOBUFS) {
            printf("losing packets!\n");
            continue;
        }
        perror("recv failed");
        break;
    }

    printf("unbinding from queue 0\n");
    nfq_destroy_queue(qh);

#ifdef INSANE
    /* normally, applications SHOULD NOT issue this command, since
     * it detaches other programs/sockets from AF_INET, too ! */
    printf("unbinding from AF_INET\n");
    nfq_unbind_pf(h, AF_INET);
#endif

    printf("closing library handle\n");
    nfq_close(h);

    return;
}

void downstreamDedup()
{
    // create the global data structures
    // create an NF queue to get packets, tie this to queue 0
    initializeRabin(powers);
    createQueue(DOWN_BASE_STATION_QUEUE, &cbDown);
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
