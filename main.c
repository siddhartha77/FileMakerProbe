#include <stdio.h>

#include <SIOUX.h>

#include <Files.h>
#include <Memory.h>
#include <StandardFile.h>

#include "main.h"
#include "filemaker.h"
#include "utils.h"

int main(void) {
    StrFileName         filename;
    StandardFileReply   sfReply;
    
    char                c;
    
    initApplication();
    
    printAbout();
    
    while (true) {
        getFile(&sfReply);
    
        if (sfReply.sfGood) {
            myCopyPStr(sfReply.sfFile.name, filename);
            myPStrToCStr(filename);
            printBar(sfReply.sfFile.name[0]);
            printf("%s\n", filename);
            printBar(sfReply.sfFile.name[0]);
            processDatabase(&sfReply.sfFile);
        } else {
            printf("No file selected.\n");
        }
        
        printf("\nProcess another? [Yes/No]: ");
        c = getchar();

        if (c != 'y' && c != 'Y') {
            break;
        }
        
        printf("\n");
        
        /* Flush buffer */
        while (getchar() != '\n') {};
    }
    
    printf("Done.\n");
	
	return 0;
}

void processDatabase(FSSpecPtr file) {
    OSErr                   err;
    short                   refNum;
    long                    count = kFMPBlockLen;
    unsigned char           block[kFMPBlockLen];
    FMPKey                  key;
    long                    filePos;
    long                    passwordCount = 0;
    FMPPasswordHndl         passwords;
    FMPPasswordPtr          pw;
    int                     i;
    
    err = openDatabase(file, &refNum);
    
    if (err) {
        printError(err);
        return;
    }
    
    /* First search for the database key */
    do {
        /* Get filePos just for debugging purposes if there is a bad byte */
        GetFPos(refNum, &filePos); 
        err = FSRead(refNum, &count, block);
            
        if (err) {
          printError(err);
          return;
        }

    } while (!(key = FMPGetKey((FMPBlockPtr)block, filePos)));
    
    if (key) {
#ifdef __DEBUG__
        printf("Key: 0x%04x\n", key);
#endif
    } else {
        printf("No key found. Is the database password protected?\n");
    }
    
    /* Next search for the Access Block that contains the passwords */
    do {
        GetFPos(refNum, &filePos);        
        err = FSRead(refNum, &count, block);
       
        if (err) {
            printError(err);
            return;
        }
    } while (!FMPIsAccessBlock((FMPBlockPtr)block, filePos));

#ifdef __DEBUG__
    printf("Access Block found at 0x%04x\n", filePos);
#endif

    closeDatabase(refNum);
    
    passwords = (FMPPasswordHndl)NewHandle(kMaxPasswordCount * sizeof(FMPPassword));
    HLock((Handle)passwords);
    FMPGetPasswords((FMPBlockPtr)block, passwords, &passwordCount, filePos);
    printf("\nPasswords:\n");
    
    for (i = 0 ; i < passwordCount ; ++i) {
        pw = &(*passwords)[i];
        FMPDecryptPassword(pw, key);
        printf("%02d. %s", i + 1, pw->password);
        
        if (pw->accessFlag == kFMPPasswordFullAccess) {
            printf(" [Full Access]");
        }
        
        printf("\n");
    }
    
    HUnlock((Handle)passwords);
    DisposeHandle((Handle)passwords);
}

void printError(OSErr err) {
    switch (err) {
        case noErr:
            break;
        case eofErr:
            printf("ERROR: End-of-file reached.\n");
            break;
        case kErrBadFMPDatabase:
            printf("ERROR: Not a valid FMPPro 3 database.\n");
            break;
        default:
            printf("ERROR: %d\n", err);
            break;
    }
}

OSErr openDatabase(FSSpecPtr file, short *refNum) {
    OSErr           err;
    long            count = kFMPMagicHeaderLen;
    unsigned char   header[kFMPMagicHeaderLen];
    
    /* Open the data fork */
    err = FSpOpenDF(file, fsRdPerm, refNum);
    if (err != noErr) return err;

    /* Check if the database is valid */
    err = FSRead(*refNum, &count, header);
    
    if (err || count != kFMPMagicHeaderLen) return err;
    
    if (!FMPIsValidDatabase(header)) return kErrBadFMPDatabase;

    /* Set the file mark to the starting position */
    err = SetFPos(*refNum, fsFromStart, kFMPStartingOffset);

    return err;
}

OSErr closeDatabase(short refNum) {
    OSErr   err;
    
    err = FSClose(refNum);
    
    return err;
}

void printAbout() {
    printf("FileMaker Probe v1.0\nsiddhartha, 2024\nhttps://github.com/siddhartha77/FileMakerProbe\n");
    printBar(46);
    printf("\n");
}

void printBar(short len) {
    short   i;
    
    for (i = 0 ; i < len ; ++i) {
        printf("=");
    }
    
    printf ("\n");
}

void initApplication() {
    SIOUXSettings.initializeTB = false;
    SIOUXSetTitle("\pFileMaker Probe");
    
    InitGraf(&qd.thePort);
	InitFonts();
	InitWindows();
	InitMenus();
	TEInit();
	InitDialogs(NULL);
	InitCursor();
    
    MaxApplZone();
}

void getFile(StandardFileReply *sfReply) {   
    SFTypeList          sfTypeList = {kFMP3Type, kFMP5Type};
    
    StandardGetFile(NULL, kTypeCount, sfTypeList, sfReply);
}