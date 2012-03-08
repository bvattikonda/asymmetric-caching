#include "as_mobile.h"

/*
 * @series: the byte sequence on which covar_matrix has to be run
 * @series_len: not used in this function, but denotes the size of
 * series, would be useful if segfaults have to be debugged
 * @start: the point from where series should be considered to compute
 * covar_matrix
 */
dMatrix *covar_matrix(unsigned char *series, uint32_t series_len,
        uint32_t start, uint32_t length) {
    assert(length > ARORDER);
    dMatrix *c_matrix = new dMatrix(ARORDER + 1, ARORDER + 1, 0.0);
    double n_dash = length - ARORDER;
    for(int i = 0; i < ARORDER + 1; i++) {
        uint32_t covar_sum = 0;
        for(int j = ARORDER; j < (int)length; j++) {
            covar_sum += (series[start + j]) * (series[start + j -
                    i]);
        }
        (*c_matrix)[0][i] = (covar_sum / n_dash);
    }

    for(int i = 1; i < ARORDER + 1; i++) {
        for(int j = i; j < ARORDER + 1; j++) {
            int minus = series[start + length - i] * series[start +
                length - j];
            int plus = series[start + ARORDER - i] * series[start +
                ARORDER - j];
            (*c_matrix)[i][j] = (*c_matrix)[i - 1][j - 1] -
                (double)((minus - plus) / n_dash);
        }
        for(int j = 0; j < i; j++) {
            (*c_matrix)[i][j] = (*c_matrix)[j][i];
        }
    }

    return c_matrix;
}

dMatrix *pool_covar(dMatrix *c_grow, dMatrix *c_slide, unsigned char
*series, uint32_t series_len, uint32_t index, uint32_t sample_len) {
    double n_grow_dash = index - ARORDER;
    double n_slide_dash = sample_len - index - ARORDER;
    double n_dash = sample_len - ARORDER;

    dMatrix *c_matrix = new dMatrix(ARORDER + 1, ARORDER + 1, 0.0);
    /* compute all the elements in first row from c_grow and c_slide
     * */
    for(int i = 0; i < ARORDER + 1; i++) {
        double covar_sum = n_grow_dash * (*c_grow)[0][i] +
            n_slide_dash * (*c_slide)[0][i];
        for(int j = 0; j < ARORDER; j++) {
            covar_sum += series[index + j] * series[index + j - i];
        }
        (*c_matrix)[0][i] = covar_sum / n_dash;
    }

    /* derive the rest of the elements from that in the first row */
    for(int i = 1; i < ARORDER + 1; i++) {
        for(int j = i; j < ARORDER + 1; j++) {
            int minus = series[sample_len - i] * series[sample_len -
                j];
            int plus = series[ARORDER - i] * series[ARORDER - j];
            (*c_matrix)[i][j] = (*c_matrix)[i - 1][j - 1] - (minus -
                    plus) / n_dash;
        }

        for(int j = 0; j < i; j++) {
            (*c_matrix)[i][j] = (*c_matrix)[j][i];
        }
    }
    return c_matrix;
}

double gain(dMatrix *c_grow) {
    dMatrix cross_covar(ARORDER, 1, 0.0);
    dMatrix past_covar(ARORDER, ARORDER, 0.0);
    for(int i = 0; i < ARORDER; i++){
        cross_covar[i][0] = (*c_grow)[i + 1][0];
    }

    for(int i = 0; i < ARORDER; i++) {
        for(int j = 0; j < ARORDER; j++) {
            past_covar[i][j] = (*c_grow)[i + 1][j + 1];
        }
    }
    try {
        past_covar.inv();
    } catch (int e) {
        return -1;
    }
    dMatrix alpha = past_covar * cross_covar;
    dMatrix ar_vector(alpha.size() + 1, 1, 0.0);
    ar_vector[0][0] = 1;
    for(int i = 1; i < (int)alpha.size() + 1; i++) {
        ar_vector[i][0] = alpha[0][i - 1];
    }
    dMatrix ar_vector_transpose = ~ar_vector;
    ar_vector_transpose *= (*c_grow);
    ar_vector_transpose *= ar_vector;
    return ar_vector_transpose[0][0];
}

double get_segment_distance(dMatrix *c_grow, dMatrix *c_slide, dMatrix
        *c_pooled, uint32_t mid, uint32_t end) {
    double power_grow = gain(c_grow);
    double power_slide = gain(c_slide);
    double power_pool = gain(c_pooled);

    if(power_grow <= 0 || power_slide <= 0 || power_pool <= 0) {
        return 0;
    }

    return end * log(power_pool) - ((mid * log(power_grow)) + ((end -
                    mid) * log(power_slide)));
}

void grow_covar(dMatrix *covar_last, unsigned char *series, int n) {
    int n_dash = n - ARORDER;
    (*covar_last) *= ((n_dash - 1) / (double)n_dash);
    for(int i = 0; i < ARORDER + 1; i++) {
        for(int j = i; j < ARORDER + 1; j++) {
            (*covar_last)[i][j] = (*covar_last)[i][j] + 
                ((series[n - i - 1] * series[n - j - 1]) / (double)n_dash);
        }
        for(int j = 0; j < i; j++) {
            (*covar_last)[i][j] = (*covar_last)[j][i];
        }
    }
}

void slide_covar(dMatrix *covar_last, unsigned char *series, int n) {
    int n_dash = n - ARORDER;
    for(int i = 0; i < ARORDER + 1; i++) {
        for(int j = i; j < ARORDER + 1; j++) {
            (*covar_last)[i][j] = (*covar_last)[i][j] + 
            (((series[n - i] * series[n - j]) - 
            (series[ARORDER - i] * series[ARORDER - j]))
            / (double)n_dash);
        }
        for(int j = 0; j < i; j++) {
            (*covar_last)[i][j] = (*covar_last)[j][i];
        }
    }
}

/* @joint_packet: packet struct which gives a combination of the
 * previous packet seen on the connection and the current packet
 * @index: index on which boundary has to be searched
 * @lthresh: lower threshold
 * return true if the boundary has been detected, false otherwise
 */
bool detect_boundary(flow_packet *joint_packet, uint32_t index,
        uint32_t lthresh) {
    dMatrix *last_cgrow = covar_matrix(joint_packet->payload,
            joint_packet->payload_len, 0, index);
    dMatrix *last_cslide = covar_matrix(joint_packet->payload,
            joint_packet->payload_len, index, lthresh);

    dMatrix *new_pool = pool_covar(last_cgrow, last_cslide,
            joint_packet->payload, joint_packet->payload_len,
            index, index + lthresh);

    double segment_distance = get_segment_distance(last_cgrow,
            last_cslide, new_pool, index, index + lthresh);

    delete last_cgrow;
    delete last_cslide;
    delete new_pool;

    if(segment_distance < DTHRESH) {
        return false;
    }
    return true;
}
