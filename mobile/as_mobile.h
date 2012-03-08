#include <as_common.h>

#define ARORDER 4
#define DTHRESH 20

#define WINDOW_FACTOR 3
#define MATCH_THRESHOLD 0.70
#define ADVERTISE_COUNT (MTU / HASH_LEN)

struct hash_information {
    time_t timestamp;
    unsigned char *chunk;
    uint16_t chunk_length;
    set <uint32_t> oid_set;
};

struct object_information {
    time_t timestamp;
    uint32_t previous_oid;
    uint32_t next_oid;
    bool previous_oid_set;
    bool next_oid_set;
    list<uint64_t> hash_list;
};

struct connection{
    in_addr_t src_addr;
    uint16_t src_port;
    in_addr_t dst_addr;
    uint16_t dst_port;

    /* constructor for the tuple */
    connection(const in_addr_t _src_addr, const uint16_t _src_port,
            const in_addr_t _dst_addr, const uint16_t _dst_port) :
        src_addr(_src_addr), src_port(_src_port), dst_addr(_dst_addr),
        dst_port(_dst_port) {}

    /* a comparison operator for the map */
    bool operator<(const connection& Rhs) const {
        return (src_addr < Rhs.src_addr && src_port < Rhs.src_port &&
                dst_addr < Rhs.dst_addr && dst_port < Rhs.dst_port);
    };
};

struct flow_packet {
    unsigned char *payload;
    uint16_t payload_len;
    flow_packet() : payload(NULL), payload_len(0) {}
    ~flow_packet() {
        free(payload);
    }
};

struct chunk_hash {
    uint64_t hash_value;
    uint16_t chunk_length;
    chunk_hash(uint64_t _hash_value, uint16_t _chunk_length) :
        hash_value(_hash_value), chunk_length(_chunk_length) {}
};

typedef map<connection, flow_packet *> ConnectionSeriesType;
typedef map<connection, uint32_t> OIDMap;

typedef matrix<double> dMatrix;

bool detect_boundary(flow_packet *joint_packet, uint32_t index,
        uint32_t lthresh);

bool best_matched_flowlet(uint32_t current_oid, list<chunk_hash *>
        *payload_hash_list, set<uint32_t> *past_flowlets, uint32_t
        *best_oid);
