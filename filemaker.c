#include "filemaker.h"

#define PRINT_BAD_FIELD_BYTE_ERROR(block, payload, byte) \
    printf("ERROR: Bad field byte at block 0x%02x, payload[0x%02x] (byte == 0x%02x)\n", block, payload, byte)

uint32_t FMPIsValidDatabase(uint8_t *header) {
    uint16_t    i;
    
    for (i = 0 ; i < kFMPMagicHeaderLen ; ++i) {
        if (header[i] != FMPMagicHeader[i]) return false;
    }
    
    return true;
}

FMPKey FMPGetKey(FMPBlockPtr block, int32_t filePos) {
    uint32_t            i = 0;
    uint32_t            bytesToSkip;
    uint32_t            key;    
    FMPPayloadBytePtr   payload = block->payload;
    
    while (*((FMPFieldRefKeyMagicPtr)(&payload[i])) != kFMPFieldRefKeyMagic) {
        bytesToSkip = FMPSkipPayloadBytes(&payload[i]);
        
        /* There was probably and error here */
        if (bytesToSkip == 0) {
            PRINT_BAD_FIELD_BYTE_ERROR(filePos, i, payload[i]);
            ++i;
            return 0;
        }
        
        i += bytesToSkip;
        
        /* No key found! */
        if (i >= block->payloadLen) return 0;
    }
    
    i += sizeof(FMPFieldRefKeyMagic);
    
    key = *((FMPKeyPtr)(&payload[i + kFMPKeyOffset]));
    
    return key;
}

/* filePos is just used as a debugging tool in the even of an error */
uint32_t FMPIsAccessBlock(FMPBlockPtr block, uint32_t filePos) {
    uint32_t            i = 0;
    uint32_t            bytesToSkip;
    FMPPayloadBytePtr   payload = block->payload;

    while (*((FMPFieldRef32BitMagicPtr)(&payload[i])) != kFMPAccessBlockFieldRefMagic) {
        bytesToSkip = FMPSkipPayloadBytes(&payload[i]);
        
        /* There was probably and error here */
        if (bytesToSkip == 0) {
            PRINT_BAD_FIELD_BYTE_ERROR(filePos, i, payload[i]);
            ++i;
            return 0;
        }
        
        i += bytesToSkip;
        
        /* No key found! */
        if (i >= block->payloadLen) return 0;
    }
    
    return 1;
}

void FMPGetPasswords(FMPBlockPtr block, FMPPasswordHndl passwords, int32_t *count, int32_t filePos) {
    uint32_t                i = 0;
    uint32_t                j = 0;
    uint32_t                bytesToSkip;
    FMPPayloadBytePtr       payload = block->payload;
    FMPPasswordFieldPtr     pwField;
    FMPPasswordPtr          pw;
    FMPFieldRefSimple       fieldRef;
    FMPFieldRefSimpleLen    fieldLen;
    
    *count = 0;
    
    while (true) {
        fieldRef = *((FMPFieldRefPasswordMagicPtr)(&payload[i]));
        fieldLen = payload[i + sizeof(FMPFieldRefSimpleLen)];
        
        if ((fieldRef == kFMPFieldRefPasswordMagicType) && (fieldLen >= kFMPFieldRefPasswordMagicLen)) {
            /* Copy everything to our smaller struct to save memory */
            pwField = (FMPPasswordFieldPtr)(&payload[i]);
            pw = &((*passwords)[(*count)++]);
            pw->accessFlag = pwField->accessFlag;
            pw->salt1 = pwField->fieldLen;
            pw->salt2 = pwField->salt;
            pw->len = pwField->passwordLen;
            
            /* Copy the password over */
            for (j = 0 ; j < pw->len ; ++j) {
               pw->password[j] = pwField->password[j];
            }
            
            /* NULL terminate it */
            pw->password[j] = '\0';
        };
        
        bytesToSkip = FMPSkipPayloadBytes(&payload[i]);
        
        /* There was probably and error here */
        if (bytesToSkip == 0) {
            PRINT_BAD_FIELD_BYTE_ERROR(filePos, i, payload[i]);
            ++i;
        }
        
        i += bytesToSkip;
        
        /* No more passwords found! */
        if (i >= block->payloadLen) return;
    }    
    
    return;
}

/* Skip over fields. See filemaker.h for references. */
uint32_t FMPSkipPayloadBytes(FMPPayloadBytePtr payload) {
    FMPPayloadByte      payloadByte = *payload;
    FMP16BitFieldRef    fieldRef16Bit;
    uint32_t            bytesToSkip = 0;
    
    if (payloadByte >= kFMPDataSimpleMin && payloadByte <= kFMPDataSimpleMax) {
        bytesToSkip += sizeof(FMPDataSimple);
        bytesToSkip += payloadByte - (kFMPDataSimpleMin - 1);
        
        return bytesToSkip;
    }
    
    if (payloadByte == kFMPFieldRefSimpleID) {
        bytesToSkip += sizeof(FMPFieldRefSimple);
        payload += bytesToSkip;
        bytesToSkip += *payload;
        
        return bytesToSkip;
    }
    
    if (payloadByte >= kFMPFieldRefSimpleMin && payloadByte <= kFMPFieldRefSimpleMax) {
        bytesToSkip += sizeof(FMPFieldRefSimple);
        payload += sizeof(FMPFieldRefSimple);        
        bytesToSkip += sizeof(FMPFieldRefSimpleLen);
        bytesToSkip += *payload;
        
        return bytesToSkip;
    }
    
    if (payloadByte >= kFMPFieldRefLongMin && payloadByte <= kFMPFieldRefLongMax) {
        bytesToSkip += *payload;
        bytesToSkip += sizeof(FMPFieldRefLongID);
        payload += bytesToSkip; 
        bytesToSkip += *payload;        
        bytesToSkip += sizeof(FMPFieldRefLongLen);
        
        return bytesToSkip;
    }
    
    if (payloadByte >= kFMPPathPushLo && payloadByte <= kFMPPathPushHi) {
        bytesToSkip += sizeof(FMPPathPush);
        bytesToSkip += payloadByte - (kFMPPathPushLo - 1);
        
        return bytesToSkip;
    }
   
    if (payloadByte == kFMPPathPop) {
        bytesToSkip += sizeof(FMPPathPop);
        
        return bytesToSkip;
    }
    
    if (payloadByte == kFMP16BitFlag) {
        bytesToSkip += sizeof(FMP16BitFlag);
        payload += sizeof(FMP16BitFlag);
        
        fieldRef16Bit = *payload;
        
        if (fieldRef16Bit >= kFMP16BitLongMin && fieldRef16Bit <= kFMP16BitLongMax) {
            /* Get the ID of the field and it's ID length and skip over both */        
            bytesToSkip += sizeof(FMPFieldRefLongID);
            bytesToSkip += *((FMPPayloadBytePtr)(payload));
            payload += sizeof(FMP16BitFieldRef) + sizeof(FMPFieldRefLongLen);
        } else if (fieldRef16Bit >= kFMP16BitSimpleMin && fieldRef16Bit <= kFMP16BitSimpleMax) {
            /* There is no ID length, so skip over the single byte ID */
            bytesToSkip += sizeof(FMPFieldRefSimpleID);
            payload += sizeof(FMP16BitFieldRef);
        } else {
            /* Unknown 16Bit ID... */
            return 0;
        }
        
       /* Skip over the 16-bit data length and data */
       bytesToSkip += sizeof(FMPPayload16Bit);
       bytesToSkip += *((FMPPayload16BitPtr)(payload));
   
       return bytesToSkip;
    }
    
    return bytesToSkip;
}

void FMPDecryptPassword(FMPPasswordPtr pw, FMPKey key) {
    uint16_t    i;
    
    key += (pw->salt1 << 1) + pw->salt2;
    
    for (i = pw->len ; i > 0 ; --i) {
        if (i > 1) {
            pw->password[i - 1] ^= pw->password[i - 2] ^ (key >> i);
        } else {
            pw->password[0] ^= kFMPCryptSeed ^ (key >> 1);
        }
    }
}
