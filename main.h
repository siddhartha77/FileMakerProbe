#ifndef	__MAIN_H__
#define	__MAIN_H__

enum {
    kTypeCount  =   2,
    kFMP3Type   = 'FMP3',
    kFMP5Type   = 'FMP5'
};

enum {
    kErrBadFMPDatabase  = 1001
};

enum {
    kMaxPasswordCount   = 128
};

void    initApplication();
void    getFile(StandardFileReply *sfReply);
void    printAbout();
void    printBar(short len);
void    printError(OSErr err);

void    processDatabase(FSSpecPtr file);
OSErr   openDatabase(FSSpecPtr file, short *refNum);
OSErr   closeDatabase(short refNum);

#endif __MAIN_H__
