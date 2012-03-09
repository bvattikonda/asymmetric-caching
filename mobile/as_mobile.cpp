#include "as_mobile.h"

unsigned char *new_packet = NULL;

long long powers[256];
map<uint64_t, hash_information *> hash_memory;
map<uint32_t, object_information *> object_memory;

ConnectionSeriesType connection_series; 
OIDMap current_oid_map;
uint32_t oid_count = 0;
map<uint64_t,bool> *hashes_seen_already;

map<uint32_t, map<uint32_t, uint32_t>* > hit_count;
map<uint32_t, map<uint32_t, uint32_t>* > last_match;
map<uint32_t, map<uint32_t, uint32_t>* > last_advertised;

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

void update_object_memory(bool update_previous_oid, uint32_t
        previous_oid, uint32_t new_oid) {
    object_information *new_object = new object_information();
    new_object->timestamp = time(NULL);
    new_object->previous_oid = previous_oid;
    new_object->next_oid_set = false;
    new_object->previous_oid_set = false;
    assert(object_memory.find(new_oid) == object_memory.end());
    if(update_previous_oid) {
        object_memory[previous_oid]->next_oid = new_oid;
        new_object->previous_oid_set = true;
        object_memory[previous_oid]->next_oid_set = true;
    }
    object_memory[new_oid] = new_object;
}

uint32_t update_flowlets(connection connection_tuple, unsigned char
        *payload, uint16_t payload_len) {
    /* connection tuple seen for the first time */
    if(connection_series.find(connection_tuple) ==
        connection_series.end()) {
        update_connection_series(connection_tuple, payload, payload_len);
        update_object_memory(false, 0, oid_count);
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
        update_object_memory(true, current_oid_map[connection_tuple],
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
    uint16_t chunk_length = 0, last_marker = 0;
    uint64_t hash_value = 0;
    time_t current_time = time(NULL);
    for(int i = 0; i < num_chunks; i++) {
        chunk_length = store_marks[i] - last_marker; 
        left = 0, right = 0;
        hashlittle2((void*)(payload + last_marker), chunk_length, &right, &left);
        printlog(logfile, system_loglevel, LOG_DEBUG, "Hashing chunk"
                "from %d to %d\n", last_marker, store_marks[i]);
        hash_value = right + (((uint64_t)left)<<32);
        if(hash_memory.find(hash_value) == hash_memory.end()) {
            hash_information *chunk_information = new
                hash_information();
            chunk_information->chunk = (unsigned
                    char*)malloc(chunk_length);
            memset(chunk_information->chunk, 0, chunk_length);
            memcpy(chunk_information->chunk, payload + last_marker,
                    chunk_length);
            chunk_information->chunk_length = chunk_length;
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
    uint16_t chunk_length = 0, last_marker = 0;
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
            chunk_information->chunk_length = chunk_length;
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

/* returns a list of hashes, the receiving function must free it */
set<uint64_t> *generate_feedback(uint32_t current_oid, uint32_t best_oid) {
    /* generate feedback from this packet */
    set<uint64_t> *advertise_hashes = new set<uint64_t>;
    uint32_t anchor = 0;

    if(last_advertised.find(current_oid) == last_advertised.end()) {
        anchor = (*last_match[current_oid])[best_oid];
    } else if(last_advertised[current_oid]->find(best_oid) ==
            last_advertised[current_oid]->end()) {
        anchor = (*last_match[current_oid])[best_oid];
    } else {
        anchor = ((*last_match[current_oid])[best_oid] >
            (*last_advertised[current_oid])[best_oid]) ?
        (*last_match[current_oid])[best_oid] :
        (*last_advertised[current_oid])[best_oid];
    }

    object_information *best_object = object_memory[best_oid];
    if (anchor == best_object->hash_list.size())
        return advertise_hashes;

    bool object_changed = false, end_of_connection = false;
    list<uint64_t>::iterator best_it = best_object->hash_list.begin();
    advance(best_it, anchor);
    uint32_t advertise_oid = best_oid;
    for(int i = 0; i < ADVERTISE_COUNT; i++) {
        best_it++;
        if(best_it == best_object->hash_list.end()) {
            /* the best object has ended */
            if(best_object->next_oid_set == false) {
                /* no new object to go to, just break*/
                break;
            } 
            /* else there is a next object*/
            object_changed = true;
            /* reset anchor for this new object */
            anchor = 0;  
            /* pick the new oid */
            advertise_oid = best_object->next_oid;
            /* the new oid could have no hashes*/
            while(object_memory[advertise_oid]->hash_list.empty()) {
                /* find the next oid */
                if(!object_memory[advertise_oid]->next_oid_set) {
                    /* reached end of connection, just exit */
                    end_of_connection = true;
                    break;
                }
                advertise_oid = object_memory[advertise_oid]->next_oid;
            }
            if(end_of_connection)
                break;
            /* not end of connection, so you found a new oid, iterate
             * through it */
            int next_oid_count = 0;
            for(list<uint64_t>::iterator adv_oid_it =
                object_memory[advertise_oid]->hash_list.begin();
                adv_oid_it !=
                object_memory[advertise_oid]->hash_list.end();
                adv_oid_it++) {
                /* extract ADVERTISE_COUNT -i hashes from this*/
                if (next_oid_count == ADVERTISE_COUNT -i)
                    break;
                /* else */
                advertise_hashes->insert(*adv_oid_it);
                next_oid_count ++;
            }
            /*advertisements done, just exit the for loop*/
            break;
        }
        /* we have not reached the end of best_object, so just add the
         * next hash to advertise_hashes */
        advertise_hashes->insert(*best_it);

    }

    /* update the current anchor value in last_advertised */
    if(last_advertised.find(current_oid) == last_advertised.end()) {
        last_advertised[current_oid] = new map<uint32_t, uint32_t>;
        (*last_advertised[current_oid])[best_oid] = 0; 
    } else if(last_advertised[current_oid]->find(best_oid) ==
            last_advertised[current_oid]->end()) {
        (*last_advertised[current_oid])[best_oid] = 0; 
    }
    (*last_advertised[current_oid])[best_oid] = anchor;

    if(object_changed) {
        last_advertised[current_oid]->erase(best_oid);
        last_match[current_oid]->erase(best_oid);
        (*hit_count[current_oid])[best_oid] = 0;
    }
    return advertise_hashes;
}

void optimize_feedback(set<uint64_t> *advertise_hashes){
    for(set<uint64_t>::iterator optimize_it = advertise_hashes->begin(); optimize_it!= advertise_hashes->end();optimize_it++){
        if(hashes_seen_already->find(*optimize_it) != hashes_seen_already->end()) {
            /* hash already seen so remove it*/
            advertise_hashes->erase(optimize_it);
        }
    }
    return;
}

uint16_t recreate_original_payload(unsigned char* payload, uint16_t payload_len, struct ip* ip_hdr) {
    /* new_packet is already initialized */
    assert(ip_hdr->ip_p == DEDUP_MIXED);
    memset(new_packet, 0, sizeof(unsigned char) * MTU);
    /* packet is mixed content */
    /* iterate over it, read every 2B header and hash/unhash accordingly*/
    uint16_t new_packed_upto = 0, unpacked_upto = 0, shim_header = 0, chunk_length=0;
    uint64_t dedup_hash = 0;
    while(unpacked_upto < payload_len) {
        shim_header = ntohs(unpack_buffer(uint16_t, payload,
                    unpacked_upto));
        unpacked_upto += 2;
        if((shim_header & HASH_HDR) == HASH_HDR){
            dedup_hash = ntohs(unpack_buffer(uint64_t, payload,
                        unpacked_upto));
            unpacked_upto += HASH_LEN;
            /* unhash this value */
            if(hash_memory.find(dedup_hash) == hash_memory.end()){
                printlog(logfile, system_loglevel, LOG_CRITICAL, "*\
                        HASH collision\n" );
                continue;
            } else{
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
int dedup(struct nfq_data* buf, int *size, int flag) {
    printf("In the function dedup\n");
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
        *size = ntohs(ip_hdr->ip_len);
        return id;
    } else if (ip_hdr->ip_p == DEDUP_CLEAR) {
        /* dedup base sending a packet which was not compressed */
        ip_hdr->ip_p = IP_PROTO_TCP;
        *size = ntohs(ip_hdr->ip_len);
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
        uint32_t best_oid = 0;
        if(!best_matched_flowlet(current_oid, payload_hash_list,
            past_flowlets, &best_oid)) {
            clear_payload_hash_list(payload_hash_list);
            delete past_flowlets;
            return id;
        }
        set<uint64_t> *advertise_hashes =
            generate_feedback(current_oid, best_oid);
        /* check for advertise_hashes in hashes_seen_already and remove those */
        optimize_feedback(advertise_hashes);
        delete advertise_hashes;
        delete past_flowlets;
    } else if (ip_hdr->ip_p == DEDUP_MIXED) {
        /* dedup base sending a packet which was compressed */
        uint16_t original_payload_size = recreate_original_payload(payload,
                payload_len, ip_hdr);
        ip_hdr->ip_p = IP_PROTO_TCP;
        *size = original_payload_size + size_ip + size_tcp;
        ip_hdr->ip_len = htons(*size);
        ip_hdr->ip_sum = ip_header_checksum((uint16_t *)ip_hdr, sizeof(struct ip));
        memcpy(payload, new_packet, original_payload_size);
        uint32_t current_oid = update_flowlets(connection_tuple,
                payload, payload_len);
        set<uint32_t> *past_flowlets = get_past_flowlets(current_oid,
                payload, payload_len, payload_hash_list);
        if(past_flowlets->empty()) {
            clear_payload_hash_list(payload_hash_list);
            delete past_flowlets;
            return id;
        }
        uint32_t best_oid = 0;
        if(!best_matched_flowlet(current_oid, payload_hash_list,
            past_flowlets, &best_oid)) {
            clear_payload_hash_list(payload_hash_list);
            delete past_flowlets;
            return id;
        }
        set<uint64_t> *advertise_hashes =
            generate_feedback(current_oid, best_oid);
        /* check for advertise_hashes in hashes_seen_already and remove those */
        optimize_feedback(advertise_hashes);
        delete advertise_hashes;
        delete past_flowlets;
    }
    printlog(logfile, system_loglevel, LOG_CRITICAL, "We should not"
            "be reaching here\n");
    assert(false);
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

    nfnl_rcvbufsiz(nfq_nfnlh(h), 1024 * 4096);

    for (;;) 
    {
        if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) 
        {
            printf("pkt received\n");
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
    createQueue(DOWN_MOBILE_QUEUE, &cbDown);
    return;
}

/************************* main *******************************/
int main() {
    new_packet = (unsigned char *)malloc(MTU);
    if(new_packet == NULL) {
        printf("Malloc failed\n");
        exit(EXIT_FAILURE);
    }
    // start the downstream code, later move to a thread
    downstreamDedup();
    // start the upstream code, later move to a thread
    return 0;
}
