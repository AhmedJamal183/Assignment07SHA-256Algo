#ifndef SHA256_H
#define SHA256_H
#include <string>

#define SHA2_ShiftRight(x,n) (x >> n)
#define SHA2_RotateRight(x,n) ((x >> n) | (x << ((sizeof(x) << 3) - n)))
#define SHA2_RotateLeft(x,n) ((x << n) | (x >> ((sizeof(x) << 3) - n)))
#define SHA2_CH(x,y,z) ((x & y) ^ (~x & z))
#define SHA2_MAJ(x,y,z) ((x & y) ^ (x & z) ^ (y & z))
#define SHA256_F1(x) (SHA2_RotateRight(x,2) ^ SHA2_RotateRight(x,13) ^ SHA2_RotateRight(x,22))
#define SHA256_F2(x) (SHA2_RotateRight(x,6) ^ SHA2_RotateRight(x,11) ^ SHA2_RotateRight(x,25))
#define SHA256_F3(x) (SHA2_RotateRight(x,7) ^ SHA2_RotateRight(x,18) ^ SHA2_ShiftRight(x,3))
#define SHA256_F4(x) (SHA2_RotateRight(x,17) ^ SHA2_RotateRight(x,19) ^ SHA2_ShiftRight(x,10))
#define SHA2_UNPACK32(x,str)                \
{                                           \
    *((str)+3) = (uint8) ((x));             \
    *((str)+2) = (uint8) ((x) >> 8);        \
    *((str)+1) = (uint8) ((x) >> 16);       \
    *((str)+0) = (uint8) ((x) >> 24);       \
}
#define SHA2_PACK32(str,x)                  \
{                                           \
	*(x) = ((uint32) * ((str)+3))           \
    	| ((uint32) * ((str)+2) << 8)       \
        | ((uint32) * ((str)+1) << 16)      \
        | ((uint32) * ((str)+0) << 24);     \
}
#endif
 
class SHA256
{
	public:
	    void init();
	    void updatingHash(const unsigned char *msg, unsigned int length);
	    void finalizingHash(unsigned char *digest);
	    static const unsigned int digestSize = (256/8);
	 
	protected:
	    typedef unsigned char uint8;
	    typedef unsigned int uint32;
	    typedef unsigned long long uint64;
	    const static uint32 sha256RoundConstants[];
	    static const unsigned int SHA224BlockSize256 = (512/8);
	    void processingHash(const unsigned char *msg, unsigned int blockNB);
	    unsigned int hashTotalLength, hashLength;
	    unsigned char mBlock[2*SHA224BlockSize256];
	    uint32 hashValues[8];
};
 
std::string sha256(std::string input);
 
