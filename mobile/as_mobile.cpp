#include "as_mobile.h"

unsigned char *new_packet = NULL;

long long powers[256];
map<uint64_t, hash_information *> hash_memory;
map<uint32_t, object_information *> object_memory;

ConnectionSeriesType connection_series; 
OIDMap current_oid_map;
uint32_t oid_count = 0;

map<uint32_t, map<uint32_t, uint32_t> > hit_count;
map<uint32_t, map<uint32_t, uint32_t> > last_match;
map<uint32_t, map<uint32_t, uint32_t> > last_advertised;

FILE *logfile = fopen("as_mobile.log", "w");
uint8_t system_loglevel = LOG_DEBUG;

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

void update_connection_series(connection connection_tuple, unsigned
        char *payload, uint16_t payload_len) {
    flow_packet *packet = new flow_packet();
    packet->payload = (unsigned char *) malloc(payload_len);
    memset(packet->payload, 0, payload_len);
    memcpy(packet->payload, payload, payload_len);
    packet->payload_len = payload_len;
    connection_series[connection_tuple] = packet;
}

void update_object_memory(uint32_t previous_oid, uint32_t new_oid) {
    object_information *new_object = new object_information();
    new_object->timestamp = time(NULL);
    new_object->previous_oid = previous_oid;
    new_object->next_oid = -1;
    assert(object_memory.find(new_oid) == object_memory.end());
    if(previous_oid >= 0) {
        object_memory[previous_oid]->next_oid = new_oid;
    }
    object_memory[new_oid] = new_object;
}

uint32_t update_flowlets(connection connection_tuple, unsigned char
        *payload, uint16_t payload_len) {
    /* connection tuple seen for the first time */
    if(connection_series.find(connection_tuple) ==
        connection_series.end()) {
        update_connection_series(connection_tuple, payload, payload_len);
        update_object_memory(-1, oid_count);
        current_oid_map[connection_tuple] = oid_count;
        return oid_count++;
    }

    /* new packet on an old connection */
    flow_packet *joint_packet = new flow_packet();
    flow_packet *existing_packet =
        connection_series[connection_tuple];
    /* create packet joining existing packet and new packet */
    joint_packet->payload = (unsigned char *)malloc(payload_len +
            existing_packet->payload_len);
    joint_packet->payload_len = existing_packet->payload_len +
        payload_len;
    memset(joint_packet->payload, 0, sizeof(payload_len +
                existing_packet->payload_len));
    memcpy(joint_packet->payload, existing_packet->payload,
            existing_packet->payload_len);
    memcpy(joint_packet->payload + existing_packet->payload_len,
            payload, payload_len);

    bool boundary_present = detect_boundary(joint_packet,
            existing_packet->payload_len, payload_len); 

    update_connection_series(connection_tuple, payload, payload_len);
    if(boundary_present) {
        update_object_memory(current_oid_map[connection_tuple],
                oid_count);
        current_oid_map[connection_tuple] = oid_count;
        return oid_count++;
    }

    return current_oid_map[connection_tuple];
}

void update_hash_memory(uint32_t current_oid, unsigned char *payload,
        uint16_t payload_len) {
    /* get markers from rabin finger printing */
    uint16_t store_marks[MAX_MARKS];
    uint16_t num_chunks = rabinFingerprints(store_marks, payload,
            payload_len, powers, MIN_CHUNK_LEN);

    /* create chunks based on these markers and hash them */
    uint32_t left = 0, right = 0;
    uint16_t chunk_length = 0, last_marker = 0, packed_upto = 0;
    uint64_t hash_value = 0;
    time_t current_time = time(NULL);
    for(int i = 0; i < num_chunks; i++) {
        chunk_length = store_marks[i] - last_marker; 
        left = 0, right = 0;
        hashlittle2((void*)(payload + last_marker), chunk_length, &right, &left);
        printlog(logfile, system_loglevel, LOG_DEBUG, "Hashing chunk\
                from %d to %d\n", last_marker, store_marks[i]);
        hash_value = right + (((uint64_t)left)<<32);
        if(hash_memory.find(hash_value) != hash_memory.end()) {
            hash_information *chunk_information = new
                hash_information();
            chunk_information->chunk = (unsigned
                    char*)malloc(chunk_length);
            memset(chunk_information->chunk, 0, chunk_length);
            memcpy(chunk_information->chunk, payload + last_marker,
                    chunk_length);
            hash_memory[hash_value] = chunk_information;
        }
        hash_memory[hash_value]->timestamp = current_time;
        hash_memory[hash_value]->oid_set.insert(current_oid);
        object_memory[current_oid]->hash_list.push_back(hash_value);
    }

    /* store these hashes in the hash memory */
    object_memory[current_oid]->timestamp = current_time;
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

    /* create chunks based on these markers and hash them */
    uint32_t left = 0, right = 0;
    uint16_t chunk_length = 0, last_marker = 0, packed_upto = 0;
    uint64_t hash_value = 0;
    time_t current_time = time(NULL);
    for(int i = 0; i < num_chunks; i++) {
        chunk_length = store_marks[i] - last_marker; 
        left = 0, right = 0;
        hashlittle2((void*)(payload + last_marker), chunk_length, &right, &left);
        printlog(logfile, system_loglevel, LOG_DEBUG, "Hashing chunk\
                from %d to %d\n", last_marker, store_marks[i]);
        hash_value = right + (((uint64_t)left)<<32);
        if(hash_memory.find(hash_value) == hash_memory.end()) {
            hash_information *chunk_information = new
                hash_information();
            chunk_information->chunk = (unsigned
                    char*)malloc(chunk_length);
            memset(chunk_information->chunk, 0, chunk_length);
            memcpy(chunk_information->chunk, payload + last_marker,
                    chunk_length);
            hash_memory[hash_value] = chunk_information;
        } else {
            for(set<uint32_t>::iterator it =
                hash_memory[hash_value]->oid_set.begin();
                it != hash_memory[hash_value]->oid_set.end();
                it++) {
                past_flowlets->insert(*it);
            }
        }
        hash_memory[hash_value]->timestamp = current_time;
        hash_memory[hash_value]->oid_set.insert(current_oid);
        object_memory[current_oid]->hash_list.push_back(hash_value);
        payload_hash_list->push_back(new chunk_hash(hash_value,
                    chunk_length));
    }

    /* store these hashes in the hash memory */
    object_memory[current_oid]->timestamp = current_time;
    return past_flowlets;
}

void generate_feedback() {
    /* generate feedback from this packet */
}

void recreate_original_packet() {
}

uint32_t best_matched_flowlet(uint32_t current_oid, list<chunk_hash *>
        *payload_hash_list, set<uint32_t> *past_flowlets) {
    for(set<uint32_t>::iterator it = past_flowlets->begin(); it !=
        past_flowlets->end(); it++) {
        uint32_t past_oid = *it;

    }
}

void clear_payload_hash_list(list<chunk_hash *> *payload_hash_list) {
    for(list<chunk_hash *>::iterator it = payload_hash_list->begin();
            it != payload_hash_list->end(); it++) {
        delete *it;
    }
    delete payload_hash_list;
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

    unsigned char *pkt_ptr;
    /* get the packet from ip header onwards */
    int buf_len = nfq_get_payload(buf, (char **)&pkt_ptr); 
    
    struct ip *ip_hdr = (struct ip *)pkt_ptr;
    uint32_t size_ip = 4*ntohl(ip_hdr->ip_hl);

    if (size_ip < 20) {
        printlog(logfile, system_loglevel, LOG_CRITICAL, "* Invalid\
                IP header length: %u bytes\n", size_ip);
        return id;
    }

    if(ip_hdr->ip_p != IP_PROTO_TCP && ip_hdr->ip_p != DEDUP_CLEAR &&
        ip_hdr->ip_p != DEDUP_MIXED) {
        printlog(logfile, system_loglevel, LOG_WARN, "Received a\
                non TCP packet\n");
        return id;
    }

    // get to the IP payload
    pkt_ptr += size_ip;
    struct tcphdr *tcp_hdr = (struct tcphdr *)pkt_ptr;
    unsigned char *payload = pkt_ptr + 4 * ntohs(tcp_hdr->doff);
    uint16_t payload_len = ntohs(ip_hdr->ip_len) - 4 *
        ntohs(tcp_hdr->doff);
    list<chunk_hash *> *payload_hash_list = new list<chunk_hash *>;
    printlog(logfile, system_loglevel, LOG_DEBUG, "Payload length: %d\n", payload_len);
    connection connection_tuple(ip_hdr->ip_src.s_addr,
        ntohs(tcp_hdr->source),
        ip_hdr->ip_dst.s_addr,
        ntohs(tcp_hdr->dest));
    if (ip_hdr->ip_p == IP_PROTO_TCP) {
        /* fresh packet coming from a non dedup base station */
        uint32_t current_oid = update_flowlets(connection_tuple,
                payload, payload_len);
        update_hash_memory(current_oid, payload, payload_len);
        clear_payload_hash_list(payload_hash_list);
        return id;
    } else if (ip_hdr->ip_p == DEDUP_CLEAR) {
        /* dedup base sending a packet which was not compressed */
        ip_hdr->ip_p = IP_PROTO_TCP;
        ip_hdr->ip_sum = ip_header_checksum((uint16_t *)ip_hdr, sizeof(struct ip));
        uint32_t current_oid = update_flowlets(connection_tuple,
                payload, payload_len);
        set<uint32_t> *past_flowlets = get_past_flowlets(current_oid,
                payload, payload_len, payload_hash_list);
        if(past_flowlets->empty()) {
            clear_payload_hash_list(payload_hash_list);
            delete past_flowlets;
            return id;
        }
        uint32_t best_oid = best_matched_flowlet(current_oid,
                payload_hash_list, past_flowlets);
        generate_feedback();
        delete past_flowlets;
    } else if (ip_hdr->ip_p == DEDUP_MIXED) {
        /* dedup base sending a packet which was compressed */
        recreate_original_packet();
        uint32_t current_oid = update_flowlets(connection_tuple,
                payload, payload_len);
        set<uint32_t> *past_flowlets = get_past_flowlets(current_oid,
                payload, payload_len, payload_hash_list);
        if(past_flowlets->empty()) {
            clear_payload_hash_list(payload_hash_list);
            delete past_flowlets;
            return id;
        }
        uint32_t best_oid = best_matched_flowlet(current_oid,
                payload_hash_list, past_flowlets);
        generate_feedback();
        delete past_flowlets;
    }
    clear_payload_hash_list(payload_hash_list);
}

static int cbDown(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *payload)
{
    char *send_data;
    int i,newSize;
    u_int32_t id = dedup(nfa, &newSize,1);
    i = nfq_get_payload(nfa, &send_data);
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
    new_packet = (unsigned char *)malloc(MTU);
    if(new_packet == NULL) {
        printf("Malloc failed\n");
        exit(EXIT_FAILURE);
    }
    downstreamDedup();
    // start the downstream code, later move to a thread
    // start the upstream code, later move to a thread
    return 0;
}
