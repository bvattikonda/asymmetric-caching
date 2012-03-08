#include <util.h>

/* stupidity BE:MSB first, LE: MSB last*/
int am_big_endian(void){
    long one = 1;
    return !(*((char*)(&one))); /* looking for 1 in the big end */
}

/* pass in something at least 20 bytes long */
void ip_from_bytes(uint32_t addr, char *buf, int nbo){
    unsigned char *caddr = (unsigned char*) &addr;
    if (am_big_endian() || nbo){
        sprintf(buf,"%d.%d.%d.%d",caddr[0],caddr[1],caddr[2],caddr[3]);
    } else {
        sprintf(buf,"%d.%d.%d.%d",caddr[3],caddr[2],caddr[1],caddr[0]);
    }
    return;
}

/* 20 bytes should be good here as well */
void mac_from_bytes(unsigned char *mac, char *buf) {
    if(mac == NULL)
        return;
    sprintf(buf, "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return;
}

/*
 * Simple function to print the buffer at pg in hex. Upto len bytes are printed
 */
void dump_data(FILE *logfile, uint8_t thread_loglevel, uint8_t loglevel, unsigned char *pg, int len) {
    int i = 0;
    int loop_len = len - len % 16;
    while (i < loop_len) {
        if(logfile != NULL)
            printlog (logfile, thread_loglevel, loglevel, "%04d: %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n",
                    i, pg[i], pg[i + 1], pg[i + 2], pg[i + 3], pg[i + 4], pg[i + 5],
                    pg[i + 6], pg[i + 7], pg[i + 8], pg[i + 9], pg[i + 10], pg[i + 11],
                    pg[i + 12], pg[i + 13], pg[i + 14], pg[i + 15]);
        else
            printf("%04d: %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n",
                    i, pg[i], pg[i + 1], pg[i + 2], pg[i + 3], pg[i + 4], pg[i + 5],
                    pg[i + 6], pg[i + 7], pg[i + 8], pg[i + 9], pg[i + 10], pg[i + 11],
                    pg[i + 12], pg[i + 13], pg[i + 14], pg[i + 15]);
        i += 16;
    }

    if(i == len)
        return;

    if(logfile != NULL)
        printlog(logfile, thread_loglevel, loglevel, "%04d:", i);
    else
        printf("%04d:", i);

    for(; i < len; i++) {
        if(logfile != NULL)
            printlog(logfile, thread_loglevel, loglevel, " %02x", pg[i]);
        else
            printf(" %02x", pg[i]);
    }

    if(logfile != NULL)
        printlog(logfile, thread_loglevel, loglevel, "\n");
    else
        printf("\n");
}

/* 
 * given a pointed to the mac address prints the mac address in the right format
 */
void print_mac(unsigned char *mac) {
    printf("%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

/* 
 * Signal handler for SIGINT, just flushes all the logs and quits.
 */
void sigexit(int sig);

/* Returns a random number, needed for creating files which do not clash with
 * each other
 */
int get_random() {
    struct timespec temp;
    clock_gettime(CLOCK_MONOTONIC, &temp);
    srand(temp.tv_nsec);
    return rand();
}
