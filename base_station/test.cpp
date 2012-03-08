#include <iostream>
#include <stdio.h>

unsigned char hash_hdr[2] = {0x80, 0x00};
unsigned char chunk_hdr[2] = {'a','b'};
using namespace std;
int main()
{
    cout << "hash" << hash_hdr << '\n'; 
    cout << "chunk" << chunk_hdr << '\n'; 
    printf("hash 0x%x\n", (hash_hdr[0]<<8+hash_hdr[1]));
    return 0;
}
