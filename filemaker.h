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

/* To find the key, we search the block for kFMPFieldRefKeyMagic and 
   kFMPKeyOffset after that is the key */
enum {
    kFMPFieldRefKeyMagic    = 0x01FC,    
    kFMPKeyOffset           = 0x2D
};

/* If kFMPAccessBlockFieldRefMagic is in the block then it's
   the Access Block. */
enum {
    kFMPAccessBlockFieldRefMagic = 0xFF5801CC
};

enum {
    kFMPFieldRefPasswordMagicType   = 0x41,     /* Password type */
    kFMPFieldRefPasswordMagicLen    = 0x25,     /* Must be >= this */
    kFMPPasswordFullAccess          = 0xFF
};

/* FMP field type bytes
   For reference:
     https://github.com/qwesda/fp5dump/blob/master/fp5.grammar
     https://github.com/evanmiller/fmptools/blob/main/HACKING */
enum {
    kFMPDataSimpleMin       = 0x81,
    kFMPDataSimpleMax       = 0xBF,
    
    kFMPFieldRefSimpleID    = 0x00,
    
    kFMPFieldRefSimpleMin   = 0x40,
    kFMPFieldRefSimpleMax   = 0x7F,
    
    kFMPFieldRefLongMin     = 0x01,
    kFMPFieldRefLongMax     = 0x3F,
    
    kFMPPathPop             = 0xC0,
    
    kFMPPathPushLo          = 0xC1,
    kFMPPathPushHi          = 0xFC,
    
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

typedef uint32_t    FMPKey;
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

typedef uint16_t                    FMPFieldRefKeyMagic;
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

struct FMPPasswordField {
    FMPFieldRefSimple       fieldType;
    FMPFieldRefSimpleLen    fieldLen;
    uint8_t                 unknown1[2];
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

uint32_t    FMPIsValidDatabase(uint8_t *header);
FMPKey      FMPGetKey(FMPBlockPtr block, int32_t filePos);
uint32_t    FMPIsAccessBlock(FMPBlockPtr block, uint32_t filePos);
void        FMPGetPasswords(FMPBlockPtr block, FMPPasswordHndl passwords, int32_t *count, int32_t filePos);
uint32_t    FMPSkipPayloadBytes(FMPPayloadBytePtr payload);
void        FMPDecryptPassword(FMPPasswordPtr pw, FMPKey key);

#endif __FILEMAKER_H__