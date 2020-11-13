#include <cstdio>
#include <cstdlib>
#include <cstring>

#include "sm3.h"
#include "sha256.h"

int main(int argc, char const *argv[])
{
    unsigned char *plain=(unsigned char *)"abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd";   //64B
    unsigned char sm3_hash_out[32];
    printf("sm3:\n");
    sm3(plain,64,sm3_hash_out);
    printf("plain:%s\n",plain);
    printf("sm3_hash_out:");
    for (int i = 0; i < 32; i++)
    {
        printf("%02x",sm3_hash_out[i]);
    }
    printf("\n");
    



    unsigned char sha256_hash_out[32];
    printf("sha256:\n");
    SHA256(plain,64,sha256_hash_out);
    printf("plain:%s\n",plain);
    printf("sha256_hash_out:");
    for (int i = 0; i < 32; i++)
    {
        printf("%02x",sha256_hash_out[i]);
    }
    printf("\n");


    return 0;
}
