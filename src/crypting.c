/*
 * crypting: Hashes and Crypto in GAP
 */

#include "src/compiled.h"          /* GAP headers */

/* Implements the SHA256 hash function as per the description in
 * https://web.archive.org/web/20130526224224/http://csrc.nist.gov/groups/STM/cavp/documents/shs/sha256-384-512.pdf
 */


/* For the moment we assume the input is a
   string, we should probably have a list of bytes,
   or words or something */


static inline UInt4 RotateRight(UInt4 x, UInt4 n)
{
    UInt8 temp;
    UInt4 up, low;
    UInt4 mask;

    if(n == 0) {
        return x;
    } else {
        temp = (UInt8)(x) << (32 - (n % 32));
        mask = (1 << (32 - (n % 32))) - 1;
        low = (temp >> 32) & mask;
        up = (temp & 0xffffffff);
        return low | up;
    }
}

static inline UInt4 Ch(UInt4 x, UInt4 y, UInt4 z)
{ return (x & y) ^ (~x & z); }

static inline UInt4 Maj(UInt4 x, UInt4 y, UInt4 z)
{ return (x & y) ^ (x & z) ^ (y & z); }

static inline UInt4 Sigma0(UInt4 x)
{ return RotateRight(x, 2) ^ RotateRight(x, 13) ^ RotateRight(x, 22); }

static inline UInt4 Sigma1(UInt4 x)
{ return RotateRight(x, 6) ^ RotateRight(x, 11) ^ RotateRight(x, 25); }

static inline UInt4 sigma0(UInt4 x)
{ return RotateRight(x, 7) ^ RotateRight(x, 18) ^ (x >> 3); }

static inline UInt4 sigma1(UInt4 x)
{ return RotateRight(x, 17) ^ RotateRight(x, 19) ^ (x >> 10); }

static const UInt4 k[] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

static const UInt4 rinit[] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 };

/* TODO: These depend on endianness */
static const UInt8 ByteSwapUInt8(UInt8 x)
{
    return (((x >> 56) |
         ((x >> 40) & 0xff00) |
         ((x >> 24) & 0xff0000) |
         ((x >> 8) & 0xff000000) |
         ((x << 8) & ((UInt8)0xff << 32)) |
         ((x << 24) & ((UInt8)0xff << 40)) |
         ((x << 40) & ((UInt8)0xff << 48)) |
         ((x << 56))));
}

static const UInt4 ByteSwapUInt4(UInt4 x)
{
    return (((x >> 24) |
             ((x >> 8) & 0xff00) |
             ((x << 8) & 0xff0000) |
             ((x << 24) & 0xff000000))); 
}

Obj CRYPTING_SHA256(Obj self, Obj bytes)
{
    UInt len, plen;
    UInt blocks;
    UInt i, j, pos;
    Int bits;
    UChar *str;
    UInt4 *msg;
    UInt4 temp1, temp2;

    UInt4 r[8];
    UInt4 h[8];
    UInt4 w[64];

    Obj buffer;
    Obj result;

    len = GET_LEN_STRING(bytes);

    /* Message length needs to be a multiple of 512 bits (64 bytes) */

    /* number of 0-bits to append */
    bits = 448 - ((len*8) % 512) - 1;
    if( bits < 0 )
        bits += 512;

    plen = len + (bits >> 3) + 1 + 8;

    /* Number of 512 bit (64 byte) blocks */
    blocks = plen >> 6;

    buffer = NEW_STRING(plen);
    SET_LEN_STRING(buffer, plen);
    memcpy(CHARS_STRING(buffer), CHARS_STRING(bytes), len);

    str = CHARS_STRING(buffer);
    msg = (UInt4 *)str;

    /* Do the padding */
    str[len] = 0x80;
    for(i=1;i<(bits >> 3);i++)
        str[len+1] = 0x00;

    pos = len + (bits >> 3) + 1;
    *((UInt8 *)(&str[pos])) = ByteSwapUInt8(len * 8);

    /* Init hash */
    memcpy(h, rinit, sizeof(rinit));

    for(i=0;i<blocks;i++) {
        memcpy(r, h, sizeof(r));

        /* A block is 512bit = 64bytes */
        for(j=0;j<64;j++) {
            if(j < 16) {
                w[j] = ByteSwapUInt4(msg[(i << 4) + j]);
            } else {
                w[j] = sigma1(w[j-2]) + w[j-7] + sigma0(w[j-15]) + w[j-16];
            }
            temp1 = r[7] + Sigma1(r[4]) + Ch(r[4], r[5], r[6]) + k[j] + w[j];
            temp2 = Sigma0(r[0]) + Maj(r[0],r[1],r[2]);
            r[7] = r[6];
            r[6] = r[5];
            r[5] = r[4];
            r[4] = r[3] + temp1;
            r[3] = r[2];
            r[2] = r[1];
            r[1] = r[0];
            r[0] = temp1 + temp2;
        }

        for(j=0;j<8;j++)
            h[j] += r[j];
    }

    result = NEW_PLIST(T_PLIST, 8);
    SET_LEN_PLIST(result, 8);
    for(i=0;i<8;i++) {
        SET_ELM_PLIST(result, i+1, ObjInt_UInt(h[i]));
        CHANGED_BAG(result);
    }
    return result;
}

typedef Obj (* GVarFunc)(/*arguments*/);

#define GVAR_FUNC_TABLE_ENTRY(srcfile, name, nparam, params) \
  {#name, nparam, \
   params, \
   (GVarFunc)name, \
   srcfile ":Func" #name }

// Table of functions to export
static StructGVarFunc GVarFuncs [] = {
    GVAR_FUNC_TABLE_ENTRY("crypting.c", CRYPTING_SHA256, 1, "bytes"),

    { 0 } /* Finish with an empty entry */
};

/******************************************************************************
*F  InitKernel( <module> )  . . . . . . . . initialise kernel data structures
*/
static Int InitKernel( StructInitInfo *module )
{
    /* init filters and functions                                          */
    InitHdlrFuncsFromTable( GVarFuncs );

    /* return success                                                      */
    return 0;
}

/******************************************************************************
*F  InitLibrary( <module> ) . . . . . . .  initialise library data structures
*/
static Int InitLibrary( StructInitInfo *module )
{
    /* init filters and functions */
    InitGVarFuncsFromTable( GVarFuncs );

    /* return success                                                      */
    return 0;
}

/******************************************************************************
*F  InitInfopl()  . . . . . . . . . . . . . . . . . table of init functions
*/
static StructInitInfo module = {
 /* type        = */ MODULE_DYNAMIC,
 /* name        = */ "crypting",
 /* revision_c  = */ 0,
 /* revision_h  = */ 0,
 /* version     = */ 0,
 /* crc         = */ 0,
 /* initKernel  = */ InitKernel,
 /* initLibrary = */ InitLibrary,
 /* checkInit   = */ 0,
 /* preSave     = */ 0,
 /* postSave    = */ 0,
 /* postRestore = */ 0
};

StructInitInfo *Init__Dynamic( void )
{
    return &module;
}
