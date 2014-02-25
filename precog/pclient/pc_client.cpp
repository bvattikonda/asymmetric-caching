#include "pc_client.h"

unsigned char *new_packet = NULL;

long long powers[256];
map<uint64_t, hash_information *> hash_memory;
//map<uint32_t, object_information *> object_memory;
set<uint64_t> advertise_hashes;

//ConnectionSeriesType connection_series; 
uint32_t oid_count = 0;
map<uint64_t, bool> hashes_seen_already;

map<uint32_t, map<uint32_t, uint32_t>* > hit_count;
map<uint32_t, map<uint32_t, uint32_t>* > last_match;
map<uint32_t, map<uint32_t, uint32_t>* > last_advertised;

FILE *logfile = fopen("as_mobile.log", "w");
uint8_t system_loglevel = LOG_CRITICAL;

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

uint64_t compute_hash(unsigned char *payload, uint16_t chunked_upto,
        uint16_t chunk_length) {
    uint32_t left = 0, right = 0;
    hashlittle2((void*)(payload + chunked_upto), chunk_length, &right, &left);
    printlog(logfile, system_loglevel, LOG_DEBUG,
            "Hashing chunk from %d to %d\n",
            chunked_upto, chunked_upto + chunk_length);
    return right + (((uint64_t)left)<<32);
}

void update_hashes(uint32_t current_oid, unsigned char *payload, 
        uint16_t chunk_length, uint16_t chunked_upto, 
        uint64_t hash_value,
        time_t current_time) {
    if(hash_memory.find(hash_value) == hash_memory.end()) {
        hash_information *chunk_information = new
            hash_information();
        chunk_information->chunk = (unsigned
                char*)malloc(chunk_length);
        memset(chunk_information->chunk, 0, chunk_length);
        memcpy(chunk_information->chunk, payload + chunked_upto,
                chunk_length);
        chunk_information->chunk_length = chunk_length;
        hash_memory[hash_value] = chunk_information;
        printlog(logfile, system_loglevel, LOG_DEBUG,
                "INSERT hash_value: %llx, chunk_length: %u\n",
                hash_value, chunk_length);
    } else {
        printlog(logfile, system_loglevel, LOG_DEBUG,
                "EXISTS hash_value: %llx, chunk_length: %u\n",
                hash_value, chunk_length);
    }
    hash_memory[hash_value]->timestamp = current_time;
    //hash_memory[hash_value]->oid_set.insert(current_oid);
    //object_memory[current_oid]->hash_list.push_back(hash_value);
}

void update_hash_memory(uint32_t current_oid, unsigned char *payload,
        uint16_t payload_len) {
    /* get markers from rabin finger printing */
    uint16_t store_marks[MAX_MARKS];
    uint16_t num_chunks = rabinFingerprints(store_marks, payload,
            payload_len, powers, MIN_CHUNK_LEN);
    printlog(logfile, system_loglevel, LOG_DEBUG, "num_chunks: %d ", num_chunks);
    for(int i = 0; i < num_chunks; i++) {
        printlog(logfile, system_loglevel, LOG_DEBUG, "%d ", store_marks[i]);
    }
    printlog(logfile, system_loglevel, LOG_DEBUG, "\n");

    /* create chunks based on these markers and hash them */
    uint16_t chunk_length = 0, last_marker = 0;
    time_t current_time = time(NULL);
    uint64_t hash_value = 0;
    for(int i = 0; i < num_chunks; i++) {
        chunk_length = store_marks[i] - last_marker; 
        hash_value = compute_hash(payload, last_marker, chunk_length);
        update_hashes(current_oid, payload, chunk_length, last_marker,
                hash_value, current_time);
    }

    /* hashes of the tail */
    uint16_t chunked_upto = 0;
    if(num_chunks == 0) {
        chunked_upto = 0;
    } else {
        chunked_upto = store_marks[num_chunks - 1];
    }
    if(chunked_upto < payload_len - 1) {
        chunk_length = payload_len - chunked_upto;
        hash_value = compute_hash(payload, chunked_upto, chunk_length);
        update_hashes(current_time, payload, chunk_length,
                chunked_upto, hash_value, current_time);
    }

    /* store these hashes in the hash memory */
    //object_memory[current_oid]->timestamp = current_time;
}

/* remember to free the memory associated with the set that is being
 * returned here
 */
set<uint32_t> *get_past_flowlets(uint32_t current_oid, unsigned char *payload,
        uint16_t payload_len, list<chunk_hash *> *payload_hash_list) {
    set<uint32_t> *past_flowlets = new set<uint32_t>;
    /* get markers from rabin finger printing */
    uint16_t store_marks[MAX_MARKS];
    uint16_t num_chunks = rabinFingerprints(store_marks, payload,
            payload_len, powers, MIN_CHUNK_LEN);

    printlog(logfile, system_loglevel, LOG_DEBUG, "num_chunks: %d ", num_chunks);
    for(int i = 0; i < num_chunks; i++) {
        printlog(logfile, system_loglevel, LOG_DEBUG, "%d ", store_marks[i]);
    }
    printlog(logfile, system_loglevel, LOG_DEBUG, "\n");

    /* create chunks based on these markers and hash them */
    uint16_t chunk_length = 0, last_marker = 0;
    time_t current_time = time(NULL);
    uint64_t hash_value = 0;
    for(int i = 0; i < num_chunks; i++) {
        chunk_length = store_marks[i] - last_marker; 
        hash_value = compute_hash(payload, last_marker, chunk_length); 
        /*
        if(hash_memory.find(hash_value) != hash_memory.end()) {
            for(set<uint32_t>::iterator it =
                hash_memory[hash_value]->oid_set.begin();
                it != hash_memory[hash_value]->oid_set.end();
                it++) {
                past_flowlets->insert(*it);
            }
        }*/
        update_hashes(current_oid, payload, chunk_length, last_marker,
                hash_value, current_time);
        payload_hash_list->push_back(new chunk_hash(hash_value,
                    chunk_length));
    }
    uint16_t chunked_upto = 0;
    if(num_chunks == 0) {
        chunked_upto = 0;
    } else {
        chunked_upto = store_marks[num_chunks - 1];
    }
    if(chunked_upto < payload_len - 1) {
        chunk_length = payload_len - chunked_upto;
        hash_value = compute_hash(payload, chunked_upto, chunk_length); 
        /*
        if(hash_memory.find(hash_value) != hash_memory.end()) {
            for(set<uint32_t>::iterator it =
                hash_memory[hash_value]->oid_set.begin();
                it != hash_memory[hash_value]->oid_set.end();
                it++) {
                past_flowlets->insert(*it);
            }
        }*/
        update_hashes(current_oid, payload, chunk_length,
                chunked_upto, hash_value, current_time);
        payload_hash_list->push_back(new chunk_hash(hash_value,
                    chunk_length));
    }

    /* store these hashes in the hash memory */
    //object_memory[current_oid]->timestamp = current_time;
    return past_flowlets;
}

uint16_t recreate_original_payload(unsigned char* payload, uint16_t payload_len, struct ip* ip_hdr) {
    /* new_packet is already initialized */
    assert(ip_hdr->ip_p == DEDUP_MIXED);
    memset(new_packet, 0, sizeof(unsigned char) * MTU);
    /* packet is mixed content */
    /* iterate over it, read every 2B header and hash/unhash accordingly*/
    uint16_t new_packed_upto = 0, unpacked_upto = 0, shim_header = 0, chunk_length=0;
    uint32_t hash_left = 0, hash_right = 0;
    uint64_t dedup_hash = 0;
    while(unpacked_upto < payload_len) {
        shim_header = ntohs(unpack_buffer(uint16_t, payload,
                    unpacked_upto));
        unpacked_upto += 2;
        if((shim_header & HASH_HDR) == HASH_HDR){
            hash_left = ntohl(unpack_buffer(uint32_t, payload,
                        unpacked_upto));
            unpacked_upto += 4;
            hash_right = ntohl(unpack_buffer(uint32_t, payload,
                        unpacked_upto));
            unpacked_upto += 4;
            dedup_hash = hash_right + (((uint64_t)hash_left)<<32);
            /* unhash this value */
            if(hash_memory.find(dedup_hash) == hash_memory.end()){
                printlog(logfile, system_loglevel, LOG_CRITICAL,
                        "** Hash not present: %llx\n", dedup_hash);
                continue;
            } else{
                printlog(logfile, system_loglevel, LOG_CRITICAL,
                        "** Hash hit: %llx\n", dedup_hash);
                memcpy(new_packet + new_packed_upto,
                        hash_memory[dedup_hash]->chunk,
                        hash_memory[dedup_hash]->chunk_length);
                new_packed_upto +=
                    hash_memory[dedup_hash]->chunk_length;
            }
        } else {
            /* it's a chunk in original text */
            /* calculated length from shim_header and read the chunk*/
            chunk_length = shim_header; 
            memcpy(new_packet + new_packed_upto, payload +
                    unpacked_upto, chunk_length);
            unpacked_upto += chunk_length;
            new_packed_upto += chunk_length;
        }
    }
    assert(unpacked_upto == payload_len);
    return new_packed_upto;
}

void clear_payload_hash_list(list<chunk_hash *> *payload_hash_list) {
    for(list<chunk_hash *>::iterator it = payload_hash_list->begin();
            it != payload_hash_list->end(); it++) {
        delete *it;
    }
    delete payload_hash_list;
}

/********************* downstream code *****************************/
int dedup(struct nfq_data* buf, int *size) {
    printlog(logfile, system_loglevel, LOG_DEBUG, "******* Packet"
            " received **********\n");
    // extract the headers of the packet
    struct nfqnl_msg_packet_hdr *ph;
    ph = nfq_get_msg_packet_hdr(buf);
    int id = ntohl(ph->packet_id);

    unsigned char *pkt_ptr = NULL;
    /* get the packet from ip header onwards */
    if(nfq_get_payload(buf, (char **)&pkt_ptr) == -1) {
        printlog(logfile, system_loglevel, LOG_CRITICAL,
        "Deduplication code invoked without the packet\n");
    }
    
    struct ip *ip_hdr = (struct ip *)pkt_ptr;
    uint32_t size_ip = 4 * ip_hdr->ip_hl;

    if (size_ip < 20) {
        printlog(logfile, system_loglevel, LOG_CRITICAL, "* Invalid"
                "IP header length: %u bytes\n", size_ip);
        *size = ntohs(ip_hdr->ip_len);
        return id;
    }

    if(ip_hdr->ip_p != IP_PROTO_TCP && ip_hdr->ip_p != DEDUP_CLEAR &&
        ip_hdr->ip_p != DEDUP_MIXED) {
        printlog(logfile, system_loglevel, LOG_WARN, "Received a"
                "non TCP packet\n");
        *size = ntohs(ip_hdr->ip_len);
        return id;
    }

    /* get to the IP payload */
    struct tcphdr *tcp_hdr = (struct tcphdr *)(pkt_ptr + size_ip);
    int size_tcp = 4 * tcp_hdr->doff;

    /* get to the TCP payload */
    unsigned char *payload = (unsigned char *)(pkt_ptr + size_ip +
            size_tcp);
    uint16_t payload_len = ntohs(ip_hdr->ip_len) - size_ip - size_tcp;
    printlog(logfile, system_loglevel, LOG_DEBUG, "Length parameters,"
            "ip_len: %d, size_ip: %d, size_tcp: %d, payload_len:"
            "%d\n", ntohs(ip_hdr->ip_len), size_ip, size_tcp, payload_len);
  //  list<chunk_hash *> *payload_hash_list = new list<chunk_hash *>;
    connection connection_tuple(ip_hdr->ip_src.s_addr,
            ntohs(tcp_hdr->source),
            ip_hdr->ip_dst.s_addr,
            ntohs(tcp_hdr->dest));
    uint32_t current_oid = 0;
    if (ip_hdr->ip_p == IP_PROTO_TCP) {
        /* fresh packet coming from a non dedup base station */
        printlog(logfile, system_loglevel, LOG_DEBUG,
                "Packet type: TCP packet\n");
        update_hash_memory(current_oid, payload, payload_len);
        //clear_payload_hash_list(payload_hash_list);
        *size = ntohs(ip_hdr->ip_len);
    } else if (ip_hdr->ip_p == DEDUP_CLEAR) {
        /* dedup base sending a packet which was not compressed */
        printlog(logfile, system_loglevel, LOG_DEBUG,
                "Packet type: DEDUP_CLEAR\n");
        ip_hdr->ip_p = IP_PROTO_TCP;
        *size = ntohs(ip_hdr->ip_len);
        ip_hdr->ip_sum = ip_header_checksum((uint16_t *)ip_hdr, sizeof(struct ip));
        update_hash_memory(current_oid, payload, payload_len);
        //set<uint32_t> *past_flowlets = get_past_flowlets(current_oid, payload, payload_len, payload_hash_list);
        //delete past_flowlets;
    } else if (ip_hdr->ip_p == DEDUP_MIXED) {
        /* dedup base sending a packet which was compressed */
        printlog(logfile, system_loglevel, LOG_DEBUG,
                "Packet type: DEDUP_MIXED\n");
        uint16_t original_payload_size = recreate_original_payload(payload,
                payload_len, ip_hdr);
        ip_hdr->ip_p = IP_PROTO_TCP;
        *size = original_payload_size + size_ip + size_tcp;
        ip_hdr->ip_len = htons(*size);
        printlog(logfile, system_loglevel, LOG_DEBUG,
                "Final length parameters, ip_len: %d, size: %d\n",
                ntohs(ip_hdr->ip_len), *size);
        ip_hdr->ip_sum = ip_header_checksum((uint16_t *)ip_hdr, sizeof(struct ip));
        memcpy(payload, new_packet, original_payload_size);
        payload_len = original_payload_size;
        update_hash_memory(current_oid, payload, payload_len);
        //set<uint32_t> *past_flowlets = get_past_flowlets(current_oid, payload, payload_len, payload_hash_list);
        //delete past_flowlets;
    }
    //clear_payload_hash_list(payload_hash_list);
    return id;
}

static int cbDown(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
        struct nfq_data *nfa, void *payload) {
    char *send_data;
    int i = 0,newSize = 0;
    u_int32_t id = dedup(nfa, &newSize);
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
    qh = nfq_create_queue(h, queue_num, callback, NULL);
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

    if(nfq_set_queue_maxlen(qh, 100) < 0 ) {
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
    new_packet = (unsigned char *)malloc(MTU);
    if(new_packet == NULL) {
        printf("Malloc failed\n");
        exit(EXIT_FAILURE);
    }

    struct nfq_handle *h = get_handle();
    fd_set rfds;

    // start the downstream code, later move to a thread
    initializeRabin(powers);
    int max_fd = 0;
    int down_fd = createQueue(h, DOWN_MOBILE_QUEUE, &cbDown);
    if(down_fd > max_fd)
        max_fd = down_fd;

    /*
    int up_fd = createQueue(h, UP_MOBILE_QUEUE, &cbUp);
    if(up_fd > max_fd)
        max_fd = up_fd;
    */
    int up_fd = 0;
    printlog(logfile, system_loglevel, LOG_DEBUG, 
            "Queue packet descriptors, down_fd: %d, up_fd: %d\n",
            down_fd, up_fd);

    int n = 0, rv = 0;
    char buf[4096] __attribute__ ((aligned));
    nfnl_rcvbufsiz(nfq_nfnlh(h), 4096 * 4096);
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
        /*
        if(FD_ISSET(up_fd, &rfds)) {
            rv = recv(up_fd, buf, sizeof(buf), 0);
            if(rv < 0) {
                printlog(logfile, system_loglevel, LOG_CRITICAL, 
                        "recv call failed: %s\n", strerror(errno));
            } else {
                nfq_handle_packet(h, buf, rv);
            }
        }*/
    }

    // start the upstream code, later move to a thread
    return 0;
}
