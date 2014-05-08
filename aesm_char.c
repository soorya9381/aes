#include<stdio.h>


unsigned char AESgetSBoxValue(unsigned char);
unsigned char AESgetSBoxInvert(unsigned char );
void AESrotate(unsigned char *word);
unsigned char AESgetRconValue(unsigned char num);
void AEScore(unsigned char *word, int iteration);
void AESexpandKey(unsigned char *expandedKey, unsigned char *key, int size, size_t expandedKeySize);
void AESsubBytes(unsigned char *state);
void AESshiftRow(unsigned char *state, unsigned char nbr);
void AESshiftRows(unsigned char *state);
void AESaddRoundKey(unsigned char *state, unsigned char *roundKey);
unsigned char AESgalois_multiplication(unsigned char a, unsigned char b);
void AESmixColumn(unsigned char *column);
void AESmixColumns(unsigned char *state);
void AESaes_round(unsigned char *state, unsigned char *roundKey);
void AEScreateRoundKey(unsigned char *expandedKey, unsigned char *roundKey);
void AESaes_main(unsigned char *state, unsigned char *expandedKey, int nbrRounds);    
char AESaes_encrypt(unsigned char *input, unsigned char *output, unsigned char *key, int size);
void AESinvSubBytes(unsigned char *state);
void AESinvShiftRow(unsigned char *state, unsigned char nbr);
void AESinvShiftRows(unsigned char *state);
void AESinvMixColumn(unsigned char *column);
void AESinvMixColumns(unsigned char *state);
void AESaes_invRound(unsigned char *state, unsigned char *roundKey);
void AESaes_invMain(unsigned char *state, unsigned char *expandedKey, int nbrRounds);
char AESaes_decrypt(unsigned char *input, unsigned char *output, unsigned char *key, int size);








enum keySize{
    SIZE_16 = 16,
    SIZE_24 = 24,
    SIZE_32 = 32
};



// First declare S-Boxes and helper functions

//S-Boxes
unsigned char sbox[256] = {
    //0 1 2 3 4 5 6 7 8 9 A B C D E F
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, //0
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, //1
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, //2
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, //3
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, //4
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, //5
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, //6
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, //7
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, //8
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, //9
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, //A
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, //B
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, //C
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, //D
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, //E
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 }; //F

unsigned char rsbox[256] =
{ 0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb
    , 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb
        , 0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e
        , 0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25
        , 0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92
        , 0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84
        , 0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06
        , 0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b
        , 0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73
        , 0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e
        , 0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b
        , 0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4
        , 0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f
        , 0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef
        , 0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61
        , 0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d };

// Rcon precalculated
unsigned char Rcon[255] = {
    0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8,
    0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3,
    0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f,
    0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d,
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab,
    0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d,
    0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25,
    0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01,
    0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d,
    0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa,
    0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a,
    0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02,
    0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a,
    0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef,
    0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94,
    0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04,
    0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f,
    0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5,
    0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33,
    0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb};

unsigned char c,tmp,p,counter,hi_bit_set;
int i,j,z,w,currentSize,rconIteration;
int c1,c2,c3,c4,c5,c6,c7,c8,c9,c10,c11,c12,c13,c14;
unsigned char t[4];
unsigned char cpy[4];
unsigned char column[4];
unsigned char roundKey[16];
/* the expanded keySize */
int expandedKeySize;

/* the number of rounds */
int nbrRounds;

/* the expanded key */
unsigned char expandedKey[176];

/* the 128 bit block to encode */
unsigned char block[16];


unsigned char AESgetSBoxValue(unsigned char num)
{
    return sbox[num];
}

unsigned char AESgetSBoxInvert(unsigned char num)
{
    return rsbox[num];
}

/* Rijndael's key schedule rotate operation
 * rotate the word eight bits to the left
 *
 * rotate(1d2c3a4f) = 2c3a4f1d
 *
 * word is an char array of size 4 (32 bit)
 */
void AESrotate(unsigned char *word)
{
    c = word[0];
    for (c1 = 0; c1 < 3; c1++)
        word[c1] = word[c1+1];
    word[3] = c;
}

unsigned char AESgetRconValue(unsigned char num)
{
    return Rcon[num];
}

/*
 * Key schedule section
 */

// Key schedule Core
void AEScore(unsigned char *word, int iteration)
{

    /* rotate the 32-bit word 8 bits to the left */
    AESrotate(word);

    /* apply S-Box substitution on all 4 parts of the 32-bit word */
    for (c2 = 0; c2 < 4; ++c2)
    {
        word[c2] =  AESgetSBoxValue(word[c2]);
    }

    /* XOR the output of the rcon operation with i to the first part (leftmost) only */
    word[0] = word[0]^  AESgetRconValue(iteration);
}

/* Key expansion */
/* Rijndael's key expansion
 * expands an 128,192,256 key into an 176,208,240 bytes key
 *
 * expandedKey is a pointer to an char array of large enough size
 * key is a pointer to a non-expanded key
 */

void AESexpandKey(unsigned char *expandedKey, unsigned char *key, int size, size_t expandedKeySize)
{
    /* current expanded keySize, in bytes */
    currentSize = 0;
    rconIteration = 1;
    memset(t,0,4); // temporary 4-byte variable

    /* set the 16,24,32 bytes of the expanded key to the input key */
    for (c3 = 0; c3 < size; c3++)
        expandedKey[c3] = key[c3];
    currentSize += size;

    while (currentSize < expandedKeySize)
    {
        /* assign the previous 4 bytes to the temporary value t */
        for (c3 = 0; c3 < 4; c3++)
        {
            t[c3] = expandedKey[(currentSize - 4) + c3];
        }

        /* every 16,24,32 bytes we apply the core schedule to t
         * and increment rconIteration afterwards
         */
        if(currentSize % size == 0)
        {
            AEScore(t, rconIteration++);
        }

        /* For 256-bit keys, we add an extra sbox to the calculation */
        if(size == SIZE_32 && ((currentSize % size) == 16)) {
            for(c3 = 0; c3 < 4; c3++)
                t[c3] =  AESgetSBoxValue(t[c3]);
        }

        /* We XOR t with the four-byte block 16,24,32 bytes before the new expanded key.
         * This becomes the next four bytes in the expanded key.
         */
        for(c3 = 0; c3 < 4; c3++) {
            expandedKey[currentSize] = expandedKey[currentSize - size] ^ t[c3];
            currentSize++;
        }
    }
}

/*
 * AES Encryption
 */

void AESsubBytes(unsigned char *state)
{
    /* substitute all the values from the state with the value in the SBox
     * using the state value as index for the SBox
     */
    for (c4 = 0; c4 < 16; c4++)
        state[c4] =  AESgetSBoxValue(state[c4]);
}
void AESshiftRow(unsigned char *state, unsigned char nbr)
{
    /* each iteration shifts the row to the left by 1 */
    for (c5 = 0; c5 < nbr; c5++)
    {
        tmp = state[0];
        for (c6 = 0; c6 < 3; c6++)
            state[c6] = state[c6+1];
        state[3] = tmp;
    }
}
void AESshiftRows(unsigned char *state)
{
    /* iterate over the 4 rows and call shiftRow() with that row */
    for (c7 = 1; c7 < 4; c7++)
        AESshiftRow(state+c7*4, c7);
}



void AESaddRoundKey(unsigned char *state, unsigned char *roundKey)
{
    for (c8 = 0; c8 < 16; c8++)
        state[c8] = state[c8] ^ roundKey[c8] ;
}
/* Mix columns */
unsigned char AESgalois_multiplication(unsigned char a, unsigned char b)
{
    p = 0;
    for(counter = 0; counter < 8; counter++) {
        if((b & 1) == 1)
            p ^= a;
        hi_bit_set = (a & 0x80);
        a <<= 1;
        if(hi_bit_set == 0x80)
            a ^= 0x1b;
        b >>= 1;
    }
    return p;
}

void AESmixColumn(unsigned char *column)
{

    for(c9 = 0; c9 < 4; c9++)
    {
        cpy[c9] = column[c9];
    }
    column[0] =  AESgalois_multiplication(cpy[0],2) ^
        AESgalois_multiplication(cpy[3],1) ^
        AESgalois_multiplication(cpy[2],1) ^
        AESgalois_multiplication(cpy[1],3);

    column[1] =  AESgalois_multiplication(cpy[1],2) ^
        AESgalois_multiplication(cpy[0],1) ^
        AESgalois_multiplication(cpy[3],1) ^
        AESgalois_multiplication(cpy[2],3);

    column[2] =  AESgalois_multiplication(cpy[2],2) ^
        AESgalois_multiplication(cpy[1],1) ^
        AESgalois_multiplication(cpy[0],1) ^
        AESgalois_multiplication(cpy[3],3);

    column[3] =  AESgalois_multiplication(cpy[3],2) ^
        AESgalois_multiplication(cpy[2],1) ^
        AESgalois_multiplication(cpy[1],1) ^
        AESgalois_multiplication(cpy[0],3);
}

void AESmixColumns(unsigned char *state)
{

    /* iterate over the 4 columns */
    for (c10 = 0; c10 < 4; c10++)
    {
        /* construct one column by iterating over the 4 rows */
        for (c11 = 0; c11 < 4; c11++)
        {
            column[c11] = state[(c11*4)+c10];
        }

        /* apply the mixColumn on one column */
        AESmixColumn(column);

        /* put the values back into the state */
        for (c11 = 0; c11 < 4; c11++)
        {
            state[(c11*4)+c10] = column[c11];
        }
    }
}


/* AES round */
void AESaes_round(unsigned char *state, unsigned char *roundKey)
{
     AESsubBytes(state);
     AESshiftRows(state);
     AESmixColumns(state);
     AESaddRoundKey(state, roundKey);
}
void AEScreateRoundKey(unsigned char *expandedKey, unsigned char *roundKey)
{
    /* iterate over the columns */
    for (c12 = 0; c12 < 4; c12++)
    {
        /* iterate over the rows */
        for (c13 = 0; c13 < 4; c13++)
            roundKey[(c12+(c13*4))] = expandedKey[(c12*4)+c13];
    }
}


void AESaes_main(unsigned char *state, unsigned char *expandedKey, int nbrRounds)
{
    c14 = 0;


    AEScreateRoundKey(expandedKey, roundKey);
    AESaddRoundKey(state, roundKey);

    for (c14 = 1; c14 < nbrRounds; c14++) {
        AEScreateRoundKey(expandedKey + 16*c14, roundKey);
        AESaes_round(state, roundKey);
    }

    AEScreateRoundKey(expandedKey + 16*nbrRounds, roundKey);
    AESsubBytes(state);
    AESshiftRows(state);
    AESaddRoundKey(state, roundKey);
}

/* AES Encryption */
char AESaes_encrypt(unsigned char *input, unsigned char *output, unsigned char *key, int size)
{


    /* set the number of rounds */
    switch (size)
    {
        case 16:
            nbrRounds = 10;
            break;
        case 24:
            nbrRounds = 12;
            break;
        case 32:
            nbrRounds = 14;
            break;
        default:
            return 1;
            break;
    }

    expandedKeySize = (16*(nbrRounds+1));

    /* Set the block values, for the block:
     * a0,0 a0,1 a0,2 a0,3
     * a1,0 a1,1 a1,2 a1,3
     * a2,0 a2,1 a2,2 a2,3
     * a3,0 a3,1 a3,2 a3,3
     * the mapping order is a0,0 a1,0 a2,0 a3,0 a0,1 a1,1 ... a2,3 a3,3
     */

    /* iterate over the columns */
    for (i = 0; i < 4; i++)
    {
        /* iterate over the rows */
        for (j = 0; j < 4; j++)
            block[(i+(j*4))] = input[(i*4)+j];
    }

    /* expand the key into an 176, 208, 240 bytes key */
    AESexpandKey(expandedKey, key, size, expandedKeySize);
    /* encrypt the block using the expandedKey */
    AESaes_main(block, expandedKey, nbrRounds);

    /* unmap the block again into the output */
    for (i = 0; i < 4; i++)
    {
        /* iterate over the rows */
        for (j = 0; j < 4; j++)
            output[(i*4)+j] = block[(i+(j*4))];
    }
    return 0;
}

/*
 * AES Decryption: do the reverse
 */

void AESinvSubBytes(unsigned char *state)
{
    /* substitute all the values from the state with the value in the SBox
     * using the state value as index for the SBox
     */
    for (c4 = 0; c4 < 16; c4++)
        state[c4] =  AESgetSBoxInvert(state[c4]);
}

void AESinvShiftRow(unsigned char *state, unsigned char nbr)
{
    /* each iteration shifts the row to the right by 1 */
    for (c5 = 0; c5 < nbr; c5++)
    {
        tmp = state[3];
        for (c6 = 3; c6 > 0; c6--)
            state[c6] = state[c6-1];
        state[0] = tmp;
    }
}
void AESinvShiftRows(unsigned char *state)
{
    /* iterate over the 4 rows and call invShiftRow() with that row */
    for (c7 = 0; c7 < 4; c7++)
        AESinvShiftRow(state+c7*4, c7);
}

void AESinvMixColumn(unsigned char *column)
{
    for(c9 = 0; c9 < 4; c9++)
    {
        cpy[c9] = column[c9];
    }
    column[0] =  AESgalois_multiplication(cpy[0],14) ^
        AESgalois_multiplication(cpy[3],9) ^
        AESgalois_multiplication(cpy[2],13) ^
        AESgalois_multiplication(cpy[1],11);
    column[1] =  AESgalois_multiplication(cpy[1],14) ^
        AESgalois_multiplication(cpy[0],9) ^
        AESgalois_multiplication(cpy[3],13) ^
        AESgalois_multiplication(cpy[2],11);
    column[2] =  AESgalois_multiplication(cpy[2],14) ^
        AESgalois_multiplication(cpy[1],9) ^
        AESgalois_multiplication(cpy[0],13) ^
        AESgalois_multiplication(cpy[3],11);
    column[3] =  AESgalois_multiplication(cpy[3],14) ^
        AESgalois_multiplication(cpy[2],9) ^
        AESgalois_multiplication(cpy[1],13) ^
        AESgalois_multiplication(cpy[0],11);
}

void AESinvMixColumns(unsigned char *state)
{

    /* iterate over the 4 columns */
    for (c10 = 0; c10 < 4; c10++)
    {
        /* construct one column by iterating over the 4 rows */
        for (c11 = 0; c11 < 4; c11++)
        {
            column[c11] = state[(c11*4)+c10];
        }

        /* apply the invMixColumn on one column */
        AESinvMixColumn(column);

        /* put the values back into the state */
        for (c11 = 0; c11 < 4; c11++)
        {
            state[(c11*4)+c10] = column[c11];
        }
    }
}

void AESaes_invRound(unsigned char *state, unsigned char *roundKey)
{

    AESinvShiftRows(state);
    AESinvSubBytes(state);
    AESaddRoundKey(state, roundKey);
    AESinvMixColumns(state);
}
void AESaes_invMain(unsigned char *state, unsigned char *expandedKey, int nbrRounds)
{

    AEScreateRoundKey(expandedKey + 16*nbrRounds, roundKey);
    AESaddRoundKey(state, roundKey);

    for (c14 = nbrRounds-1; c14 > 0; c14--) {
        AEScreateRoundKey(expandedKey + 16*c14, roundKey);
        AESaes_invRound(state, roundKey);
    }

    AEScreateRoundKey(expandedKey, roundKey);
    AESinvShiftRows(state);
    AESinvSubBytes(state);
    AESaddRoundKey(state, roundKey);
}
/* Finally decrypt */
char AESaes_decrypt(unsigned char *input, unsigned char *output, unsigned char *key, int size)
{
    /* set the number of rounds */
    switch (size)
    {
        case 16:
            nbrRounds = 10;
            break;
        case 24:
            nbrRounds = 12;
            break;
        case 32:
            nbrRounds = 14;
            break;
        default:
            return 1;
            break;
    }

    expandedKeySize = (16*(nbrRounds+1));

    /* Set the block values, for the block:
     * a0,0 a0,1 a0,2 a0,3
     * a1,0 a1,1 a1,2 a1,3
     * a2,0 a2,1 a2,2 a2,3
     * a3,0 a3,1 a3,2 a3,3
     * the mapping order is a0,0 a1,0 a2,0 a3,0 a0,1 a1,1 ... a2,3 a3,3
     */

    /* iterate over the columns */
    for (i = 0; i < 4; i++)
    {
        /* iterate over the rows */
        for (j = 0; j < 4; j++)
            block[(i+(j*4))] = input[(i*4)+j];
    }

    /* expand the key into an 176, 208, 240 bytes key */
    AESexpandKey(expandedKey, key, size, expandedKeySize);

    /* decrypt the block using the expandedKey */
    AESaes_invMain(block, expandedKey, nbrRounds);

    /* unmap the block again into the output */
    for (i = 0; i < 4; i++)
    {
        /* iterate over the rows */
        for (j = 0; j < 4; j++)
            output[(i*4)+j] = block[(i+(j*4))];
    }
    return 0;
}

int main() {

    int i,j;    
    unsigned char input[16]= {'H', 'e','l','l','o', '!', 'h', 'o','w','a','r','e','y','o','u', '!'};
    unsigned char output[16];
    unsigned char decrypt[16];
    int size = 16;
    unsigned char key[16] = {0x00,0x01,0x02,0x03,0x05,0x06,0x07,0x08,0x0A,0x0B,0x0C,0x0D,0x0F,0x10,0x11,0x12};
    AESaes_encrypt(input, output, key, size);

    printf("\n Original Dta Data  \n");
    for(i=0;i<16;i++){
        printf("%c \t", input[i]);
    }

    printf("\n Encrypted Data  \n");
    for(i=0;i<16;i++){
        printf("%c \t", output[i]);
    }

    AESaes_decrypt(output, decrypt, key, size);

    printf("\n Original Data  \n");
    for(i=0;i<16;i++){
        printf("%c \t", decrypt[i]);
    }

    printf("\n");



}







