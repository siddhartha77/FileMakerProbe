#ifndef	__UTILS_H__
#define	__UTILS_H__

void    myPStrToCStr(Str255 s);
void    myCopyPStr(const Str255 s, Str255 t);
void    myInsertInPStr(Str255 s,const Str255 insertStr,short offset);
short   myFindFirstInPStr(const Str255 s,unsigned char c);
void    myDeleteElementFromPStr(Str255 s,unsigned short index);
void    myReplaceCharWithPStrInPStr(Str255 s, unsigned char c, const Str255 insertStr);

#endif __UTILS_H__
