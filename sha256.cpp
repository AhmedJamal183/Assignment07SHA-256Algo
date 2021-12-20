#include <cstring>
#include <fstream>
#include "sha256.h" //header file

//Initializing hash values first 32 bits of the fractional parts of the square roots of the first 8 primes 2..19)
void SHA256::init()
{
    hashValues[0] = 0x6a09e667;
    hashValues[1] = 0xbb67ae85;
    hashValues[2] = 0x3c6ef372;
    hashValues[3] = 0xa54ff53a;
    hashValues[4] = 0x510e527f;
    hashValues[5] = 0x9b05688c;
    hashValues[6] = 0x1f83d9ab;
    hashValues[7] = 0x5be0cd19;
    hashLength = 0;
    hashTotalLength = 0;
}

//Initializing array of round constants first 32 bits of the fractional parts of the cube roots of the first 64 primes
const unsigned int SHA256::sha256RoundConstants[64] = 
    {0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
	0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};
 
void SHA256::processingHash(const unsigned char *msg, unsigned int blockNB)
{
	//create a 64-entry msg schedule array w[0..63] of 32-bit words
    uint32 w[64],workingVariables[8],t1,t2;
    const unsigned char *subBlock;
    int i,j;
    //Process the msg in successive 512-bit chunks:
    for (i=0; i<(int)blockNB; i++) 
	{
        subBlock = msg+(i<<6);
        //copy chunk into first 16 words w[0..15] of the msg schedule array
        for(j=0; j<16; j++){
            SHA2_PACK32(&subBlock[j<<2], &w[j]);
        }
        //Extend the first 16 words into the remaining 48 words w[16..63] of the msg schedule array:
        for(j=16; j<64; j++){
            w[j] = SHA256_F4(w[j-2]) + w[j-7] + SHA256_F3(w[j-15]) + w[j-16];
        }
        //Initialize working variables to current hash value:
        for(j=0; j<8; j++){
            workingVariables[j] = hashValues[j];
        }
        //Compression function main loop:
        for(j=0; j<64; j++){
            t1 = workingVariables[7] + SHA256_F2(workingVariables[4]) + SHA2_CH(workingVariables[4],workingVariables[5],workingVariables[6]) + sha256RoundConstants[j] + w[j];
            t2 = SHA256_F1(workingVariables[0]) + SHA2_MAJ(workingVariables[0],workingVariables[1],workingVariables[2]);
            workingVariables[7] = workingVariables[6];
            workingVariables[6] = workingVariables[5];
            workingVariables[5] = workingVariables[4];
            workingVariables[4] = workingVariables[3] + t1;
            workingVariables[3] = workingVariables[2];
            workingVariables[2] = workingVariables[1];
            workingVariables[1] = workingVariables[0];
            workingVariables[0] = t1+t2;
        }
        //Add the compressed chunk to the current hash value:
        for(j=0; j<8; j++){
            hashValues[j] += workingVariables[j];
        }
    }
}
 
void SHA256::updatingHash(const unsigned char *msg,unsigned int length)
{
    unsigned int blockNB, newLength, remLength, tempLength;
    const unsigned char *shiftedMsg;
    tempLength = SHA224BlockSize256 - hashLength;
    remLength = length < tempLength ? length : tempLength;
    memcpy(&mBlock[hashLength], msg, remLength);
    if (hashLength + length < SHA224BlockSize256) {
        hashLength += length;
        return;
    }
    newLength = length - remLength;
    blockNB = newLength / SHA224BlockSize256;
    shiftedMsg = msg + remLength;
    processingHash(mBlock, 1);
    processingHash(shiftedMsg, blockNB);
    remLength = newLength % SHA224BlockSize256;
    memcpy(mBlock, &shiftedMsg[blockNB << 6], remLength);
    hashLength = remLength;
    hashTotalLength += (blockNB + 1) << 6;
}

//Produce the finalizingHash hash value (big-endian):
void SHA256::finalizingHash(unsigned char *digest)
{
    unsigned int blockNB, pmLength, bLength;
    int i;
    blockNB = (1 + ((SHA224BlockSize256 - 9) < (hashLength % SHA224BlockSize256)));
    bLength = (hashTotalLength + hashLength) << 3;
    pmLength = blockNB << 6;
    memset(mBlock + hashLength, 0, pmLength - hashLength);
    mBlock[hashLength] = 0x80;
    SHA2_UNPACK32(bLength,mBlock + pmLength - 4);
    processingHash(mBlock,blockNB);
    for (i=0 ; i<8; i++) {
        SHA2_UNPACK32(hashValues[i], &digest[i<<2]);
    }
}
 
std::string sha256(std::string textInput)
{
    unsigned char digest[SHA256::digestSize];
    memset(digest, 0, SHA256::digestSize);
 
    SHA256 ctx = SHA256();
    ctx.init();
    ctx.updatingHash((unsigned char*)textInput.c_str(),textInput.length());
    ctx.finalizingHash(digest);
 
    char buf[2*SHA256::digestSize+1];
    buf[2*SHA256::digestSize] = 0;
    for (int i=0; i<SHA256::digestSize; i++)
        sprintf(buf + i*2, "%02x", digest[i]);
    return std::string(buf);
}
