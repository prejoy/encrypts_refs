#ifndef __CRC_H__
#define __CRC_H__

#ifdef __cplusplus
extern "C"{
#endif


/*
poly 为CRC迭代计算的多项式，CRC8，CRC16，CRC32等都是有标准值的，这个可以查到。
这个值是crc计算所必须的，且一般多项式就是用那么几个。

在实际运用中，因为CRC有些地方不确定，以及一点点的不足，所以加了以下一些参数完善crc计算，参数会影响结果。
不同的CRC算法，如CRC32，poly都是一样的，但下面的参数不一样，就会衍生所谓的CRC32-BZIP2算法等等,crc16,crc8同理，仅仅是初始时填的参数不同。

InitValue 为 CRC校验值的初始值，CRC在校验时，会设定这个结果的初值，一般为-1或0，这个会影响到最终结果
xorvalue 为CRC检验后的异或运算值，crc的校验结果出来后会再与它进行一次异或运算，为最终值，一般为0或-1，也会影响到最终结果。
InputReverse，OutputReverse指示数据是否要反转，用来反转输入数据的，crc8下就把数据按8比特翻转，bit7<->bit0,bit6<->bit1，等等



另外，crc计算的核心部分其实是一个有规律的循环，所以软件优化时都是用查表法，快速得到结果，一个poly多项式对应一份表，不同的多项式表不同。
可以事先计算好，在核心的循环运算时，查表可以大大提高效率，有的crc是硬件完成的，原理也是一样的。

这里不使用查表，直接计算，通用，效率低。
*/



typedef struct
{
	unsigned char poly;//多项式
	unsigned char InitValue;//初始值
	unsigned char xorvalue;//结果异或值
	int InputReverse;
	int OutputReverse;
}CRC_8;
 
typedef struct
{
	unsigned short poly;//多项式
	unsigned short InitValue;//初始值
	unsigned short xorvalue;//结果异或值
	int InputReverse;
	int OutputReverse;
}CRC_16;
 
typedef struct
{
	unsigned int poly;//多项式
	unsigned int InitValue;//初始值
	unsigned int xorvalue;//结果异或值
	int InputReverse;
	int OutputReverse;
}CRC_32;
 
extern const CRC_8 crc_8;
extern const CRC_8 crc_8_ITU;
extern const CRC_8 crc_8_ROHC;
extern const CRC_8 crc_8_MAXIM;
extern const CRC_8 crc_8_CDMA2000;
extern const CRC_8 crc_8_WCDMA;

extern const CRC_16 crc_16;
extern const CRC_16 crc_16_IBM;
extern const CRC_16 crc_16_ARC;
extern const CRC_16 crc_16_MAXIM;
extern const CRC_16 crc_16_USB;
extern const CRC_16 crc_16_MODBUS;
extern const CRC_16 crc_16_CCITT;
extern const CRC_16 crc_16_CCITT_FALSE;
extern const CRC_16 crc_16_X25;
extern const CRC_16 crc_16_XMODEM;
extern const CRC_16 crc_16_DNP;

extern const CRC_32 crc_32;
extern const CRC_32 crc_32_MPEG2;
extern const CRC_32 crc_32_BZIP2;
extern const CRC_32 crc_32_POSIX;
extern const CRC_32 crc_32_JAMCRC;
 
unsigned char crc8(unsigned char *addr, int num,const CRC_8 *type);
unsigned short crc16(unsigned char *addr, int num,const CRC_16 *type);
unsigned int crc32(unsigned char *addr, int num,const CRC_32 *type);


#ifdef __cplusplus
}
#endif

 
#endif
