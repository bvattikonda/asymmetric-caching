#include <stdio.h>
#include <string.h>
#include <iostream>
#include <cstdlib>
#include <inttypes.h>

using namespace std;
// Rabin macros
#define RABIN_PRIME 1048583
#define RABIN_MOD 256
#define RABIN_WINDOW 8

int expo(long long value,long long expo,long long mod);

void initializeRabin(long long valueList[]);

uint16_t rabinFingerprints(uint16_t markers[], u_char* payload, int pay_len,
        long long valueList[], int min_len);
