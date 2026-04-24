#ifndef	__FILEMAKER_H__
#define	__FILEMAKER_H__

#include <stdio.h>
#include <stdint.h>

#pragma options align=mac68k

#define true    1
#define false   0

enum {
    kFMPMagicHeaderLen      = 15,
    kFMPBlockLen            = 0x400,
    
    /* Where to start processing the input file */
    kFMPStartingOffset      = 0x1000
};

/* To find the key, we search the block for kFMPFieldRefKeyMagicType/Len/ID and 
   kFMPKeyOffset after that is the key */
enum {
    kFMPFieldRefKeyMagicType    = 0x01,
    kFMPFieldRefKeyMagicLen     = 0xFC,
    kFMPFieldRefKeyMagicID      = 0xEC,
    kFMPKeyOffset               = 0x2B
};

/* A password field is:
    41 29 33 07 FF 05 ... A8 31 52 89 7F D2
    MB FL RD UN AC PL UN  S2 P1 P2 P3 P4 P5
    
    MB: Password field type (kFMPFieldRefPasswordMagicType)
    FL: Password field length -- must be >= 24 (kFMPFieldRefPasswordMagicLen)
    RD: Random byte
    UN: Unknown/irrelevant data
    AC: Access bits (kFMPPasswordFullAccess is 0xFF)
    PL: Password length
    UN: Unknown/irrelevant data
    S2: salt2 (salt1 is FL)
    Pn: Password bytes (of length n)
*/

enum {
    kFMPFieldRefPasswordMagicType   = 0x41,
    kFMPFieldRefPasswordMagicLen    = 0x24,
    kFMPPasswordFullAccess          = 0xFF,
    kFMPPasswordMaxLen              = 31
};

/* FMP field type bytes
   For reference:
     https://github.com/qwesda/fp5dump/blob/master/fp5.grammar
     https://github.com/evanmiller/fmptools/blob/main/HACKING */
enum {
    kFMPDataSimpleMin       = 0x80,
    kFMPDataSimpleMax       = 0xBF,
    
    kFMPFieldRefSimpleID    = 0x00,
    
    kFMPFieldRefSimpleMin   = 0x40,
    kFMPFieldRefSimpleMax   = 0x7F,
    
    kFMPFieldRefLongMin     = 0x01,
    kFMPFieldRefLongMax     = 0x3F,
    
    kFMPPathPop             = 0xC0,
    
    kFMPPathPushLo          = 0xC1,
    kFMPPathPushHi          = 0xFE,
    
    /* 2-byte data length */
    kFMP16BitFlag           = 0xFF,
    kFMP16BitSimpleMin      = 0x40,
    kFMP16BitSimpleMax      = 0x80,
    kFMP16BitLongMin        = 0x01,
    kFMP16BitLongMax        = 0x04
};

/* Seed for the password encryption */
enum {
    kFMPCryptSeed           = 0x55
};

typedef int32_t     FMPKey;
typedef FMPKey*     FMPKeyPtr;

typedef uint8_t     FMPDataSimple;
typedef uint8_t     FMPFieldRefSimple;
typedef uint8_t     FMPFieldRefSimpleID;
typedef uint8_t     FMPFieldRefSimpleLen;
typedef uint8_t     FMPFieldRefLong;
typedef uint8_t     FMPFieldRefLongID;
typedef uint8_t     FMPFieldRefLongLen;
typedef uint32_t    FMPFieldRefDataLong;
typedef uint8_t     FMPFieldRefIDLen;
typedef uint8_t     FMPPathPush;
typedef uint8_t     FMPPathPop;
typedef uint8_t     FMP16BitFlag;
typedef uint8_t     FMP16BitFieldRef;

typedef uint16_t                    FMPPayload16Bit;
typedef FMPPayload16Bit*            FMPPayload16BitPtr;

typedef uint32_t                    FMPFieldRefKeyMagic;
typedef FMPFieldRefKeyMagic*        FMPFieldRefKeyMagicPtr;

typedef FMPFieldRefSimple           FMPFieldRefPasswordMagic;
typedef FMPFieldRefPasswordMagic*   FMPFieldRefPasswordMagicPtr;

typedef uint32_t                    FMPFieldRef32BitMagic;
typedef FMPFieldRef32BitMagic*      FMPFieldRef32BitMagicPtr;

typedef uint8_t                     FMPPayloadByte;
typedef FMPPayloadByte*             FMPPayloadBytePtr;

/* Each block is 0x400 (1024) bytes */
struct FMPBlock {
    uint8_t                 isDeleted;          /* 1 = Yes, 0 = No */
    uint8_t                 indexLevel;
    uint32_t                previousBlockID;    /* Doubly linked list */
    uint32_t                nextBlockID;
    uint16_t                reserved;
    uint16_t                payloadLen;
    FMPPayloadByte          payload[0x3F2];     /* Can be shortened to payloadLen */
};
typedef struct FMPBlock     FMPBlock;
typedef struct FMPBlock*    FMPBlockPtr;

struct FMPKeyField {
    FMPFieldRefLong         fieldType;
    FMPFieldRefLongLen      fieldLen;
    FMPFieldRefLongID       fieldID;
};
typedef struct FMPKeyField  FMPKeyField;
typedef FMPKeyField*        FMPKeyFieldPtr;

struct FMPPasswordField {
    FMPFieldRefSimple       fieldType;
    FMPFieldRefSimpleLen    fieldLen;
    uint8_t                 random;
    uint8_t                 passwordFlag;
    uint8_t                 accessFlag;
    uint8_t                 passwordLen;
    uint8_t                 unknown2[31];
    uint8_t                 salt;
    uint8_t                 password[32];
};
typedef struct FMPPasswordField  FMPPasswordField;
typedef FMPPasswordField*        FMPPasswordFieldPtr;

struct FMPPassword {
    uint8_t                 accessFlag;
    uint8_t                 salt1;
    uint8_t                 salt2;
    uint8_t                 len;
    uint8_t                 password[32];
};
typedef struct FMPPassword  FMPPassword;
typedef FMPPassword*        FMPPasswordPtr;
typedef FMPPasswordPtr*     FMPPasswordHndl;

/* Magic bytes in the file header */
static uint8_t FMPMagicHeader[kFMPMagicHeaderLen] = {
    0x00, 0x01, 0x00, 0x00,
    0x00, 0x02, 0x00, 0x01,
    0x00, 0x05, 0x00, 0x02,
    0x00, 0x02, 0xC0
};

static const uint8_t FMPNoPasswordStr[] = "(no password)";

uint32_t    FMPIsValidDatabase(uint8_t *header);
FMPKey      FMPGetKey(FMPBlockPtr block, int32_t filePos);
void        FMPGetPasswords(FMPBlockPtr block, FMPPasswordHndl passwords, int32_t *count, int32_t filePos);
uint32_t    FMPSkipPayloadBytes(FMPPayloadBytePtr payload);
void        FMPDecryptPassword(FMPPasswordPtr pw, FMPKey key);

#endif __FILEMAKER_H__
