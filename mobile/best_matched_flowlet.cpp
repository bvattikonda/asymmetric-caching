#include "as_mobile.h"

extern map<uint32_t, object_information *> object_memory;

extern map<uint32_t, map<uint32_t, uint32_t>* > hit_count;
extern map<uint32_t, map<uint32_t, uint32_t>* > last_match;
extern map<uint32_t, map<uint32_t, uint32_t>* > last_advertised;

void update_global_state(uint32_t past_oid, uint32_t current_oid,
        list<chunk_hash *> *payload_hash_list) {
    if(last_match.find(current_oid) == last_match.end()) {
        last_match[current_oid] = new map<uint32_t, uint32_t>;
        (*last_match[current_oid])[past_oid] = 0; 
    } else if(last_match[current_oid]->find(past_oid) ==
            last_match[current_oid]->end()) {
        (*last_match[current_oid])[past_oid] = 0; 
    }

    if(hit_count.find(current_oid) == hit_count.end()) {
        hit_count[current_oid] = new map<uint32_t, uint32_t>;
        (*hit_count[current_oid])[past_oid] = 0;
    } else if(hit_count[current_oid]->find(past_oid) ==
            hit_count[current_oid]->end()) {
        (*hit_count[current_oid])[past_oid] = 0;
    }

    object_information *last_object = object_memory[past_oid];
    list<uint64_t>::iterator it = last_object->hash_list.begin();
    assert((*last_match[current_oid])[past_oid] <
            last_object->hash_list.size());
    advance(it, (*last_match[current_oid])[past_oid]);
    
    int num_hashes = payload_hash_list->size();
    bool seen[num_hashes];
    for(int i = 0; i < num_hashes; i++) {
        seen[i] = false;
    }

    int count = 0, hash_index = 0;
    int window_size = payload_hash_list->size() * WINDOW_FACTOR;
    uint32_t final_match_index = 0;
    for(; it != last_object->hash_list.end(); it++) {
        hash_index = 0;
        for(list<chunk_hash *>::iterator hash_it =
            payload_hash_list->begin(); hash_it !=
            payload_hash_list->end(); hash_it++) {
            if((*hash_it)->hash_value == (*it)) {
                /* update hit count */
                (*hit_count[current_oid])[past_oid] +=
                    (*hash_it)->chunk_length;
                /* update last match */
                final_match_index = count;
                seen[hash_index] = true;
                bool done = true;
                for(int i = 0; i < num_hashes; i++) {
                    if(seen[i] == false) {
                        done = false;
                        break;
                    }
                }
                if(done) {
                    break;
                }
            }
            hash_index++;
        }
        if(count == window_size)
            break;
        count = count + 1;
    }
    (*last_match[current_oid])[past_oid] += final_match_index;
}

int get_top_hit_object(uint32_t current_oid, uint32_t
        *top_oids) {
    assert(hit_count.find(current_oid) != hit_count.end());
    map<uint32_t, uint32_t> *hit_map = hit_count[current_oid];
    uint32_t max_hit_count[2];
    memset(max_hit_count, 0, sizeof(uint32_t) * 2);

    int count = 0;
    uint32_t current_value = 0;
    for(map<uint32_t, uint32_t>::iterator it = hit_map->begin();
            it != hit_map->end(); it++) {
        if((*it).second > 0) {
            current_value = (*it).second; 
            if(current_value > max_hit_count[0]) {
                max_hit_count[1] = max_hit_count[0];
                top_oids[1] = top_oids[0];
                max_hit_count[0] = current_value;
                top_oids[0] = (*it).first;
                if(count < 2) {
                    count++;
                }
            } else if(current_value > max_hit_count[1]) {
                max_hit_count[1] = current_value;
                top_oids[1] = (*it).first;
                if(count < 2) {
                    count++;
                }
            }
        }
    }
    return count;
}

/* return true if a best oid has been found, false otherwise */
bool best_matched_flowlet(uint32_t current_oid, list<chunk_hash *>
        *payload_hash_list, set<uint32_t> *past_flowlets, uint32_t
        *best_oid) {
    for(set<uint32_t>::iterator it = past_flowlets->begin(); it !=
        past_flowlets->end(); it++) {
        uint32_t past_oid = *it;
        update_global_state(past_oid, current_oid, payload_hash_list);
    }
    uint32_t top_oids[2];
    memset(top_oids, 0, sizeof(uint32_t) * 2);
    int top_count = get_top_hit_object(current_oid, top_oids);
    assert(top_count >= 0 && top_count < 3);
    if(top_count == 0) {
        return false;
    }
    if(top_count == 1) {
        *best_oid = top_oids[0];
        return true;
    }
    if(top_oids[0] == current_oid) {
        double current_hitcount =
            (double)(*hit_count[current_oid])[current_oid];
        double compare_hitcount =
            (double)(*hit_count[current_oid])[top_oids[1]];
        if(compare_hitcount >= current_hitcount * MATCH_THRESHOLD) {
            *best_oid = top_oids[1];
            return true;
        } else {
            return false;
        }
    } else {
        *best_oid = top_oids[0];
        return true;
    }
}
