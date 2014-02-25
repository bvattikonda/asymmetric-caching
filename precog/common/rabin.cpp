#include <rabin.h>

int expo(long long value,long long expo,long long mod)
{
    long long temp2, answer = 1;
    int i=0;	
    //Corner cases for Mod non-positive numbers.
    if(mod == 0 || mod < 0)
    {
        printf("Modular arithmetic is not defined for 0 or negative numbers \n \n Exiting... \n");
        exit(1);
    }
    temp2 = expo;
    while(temp2)
    {
        i++;
        temp2 = temp2>>1;
    }
    for(;i>0;i--)
    {
        answer = (answer * answer) % mod;
        if(expo>>(i-1)&1)
        {
            answer = (answer * value) % mod;
        }
    }
    return answer;
}

// initialize rabin
void initializeRabin(long long valueList[])
{
    int i;
    long long q1 = expo(RABIN_PRIME, RABIN_WINDOW - 1, RABIN_MOD);
    for(i=0;i<256;i++)
        valueList[i] = i * q1;
    return;
}

// rabin fingerprints
uint16_t rabinFingerprints(uint16_t markers[], u_char* payload, int pay_len, long long valueList[], int min_len)
{
    // returns the number of markers found in the packet, the actual marker locations are stored in 'markers' 
    uint16_t j = 0;
    int result = 0,result_mod = 0, last_hit = 0, last_mark = 0, too_small = 0;
    int i = 0;
    for(i = 0; i < RABIN_WINDOW; i++)
    {
        result += (int)payload[i] * expo(RABIN_PRIME, RABIN_WINDOW-1-i,RABIN_MOD);
    }

    result_mod = result % RABIN_MOD;
    if(!result_mod)
        markers[j++] = i;

    for(;i<pay_len;i++)
    {
        result = result - valueList[(int)payload[i-8]];
        result = result * RABIN_PRIME;
        result = result % RABIN_MOD;
        result += (int) payload[i] % RABIN_MOD;
        result_mod = result % RABIN_MOD;
        if(!result_mod && ((i-last_hit) >= min_len)) {
            markers[j++] = i;
            last_hit = i;
        }
    }
    return j; 
}
