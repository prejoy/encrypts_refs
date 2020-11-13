#include <cstdio>
#include <cstdlib>

#include "sm4.h"

int main(int argc, char const *argv[])
{
    unsigned char key[]={0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10};
    unsigned char plain[]={0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10};
    unsigned char encdata[16]={0x68,0x1e,0xdf,0x34,0xd2,0x06,0x96,0x5e,0x86,0xb3,0xe9,0x4f,0x53,0x6e,0x42,0x46};
    unsigned char out[16];

    sm4_context hsm4_enc;
    printf("sm4 enc:\n");
    sm4_setkey_enc(&hsm4_enc,key);
    sm4_crypt_ecb(&hsm4_enc,1,16,plain,out);    //sm4 加解密的明文位16字节的整数倍长度
    printf("plain:");
    for (int i = 0; i < 16; i++)
    {
        printf("%02x",plain[i]);
    }
    printf("\nkey:");
    for (int i = 0; i < 16; i++)
    {
        printf("%02x",out[i]);
    }
    printf("\n");

    printf("sm4 dec:\n");
    sm4_setkey_dec(&hsm4_enc,key);
    sm4_crypt_ecb(&hsm4_enc,1,16,encdata,out);    //sm4 加解密的明文位16字节的整数倍长度
    printf("encdata:");
    for (int i = 0; i < 16; i++)
    {
        printf("%02x",encdata[i]);
    }
    printf("\nplain:");
    for (int i = 0; i < 16; i++)
    {
        printf("%02x",out[i]);
    }
    printf("\n");


    return 0;
}
