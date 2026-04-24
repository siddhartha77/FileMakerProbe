#include <Memory.h>

#include "utils.h"

void myPStrToCStr(Str255 s) {
    short count = s[0];
    short i;
    
    for (i = 0 ; i < count ; ++i) {
        s[i] = s[i + 1];
    }
    
    s[count] = '\0';
}

void myCopyPStr(const Str255 s,Str255 t) {
	BlockMove((Ptr) s,(Ptr) t,s[0]+1);
}

void myInsertInPStr(Str255 s,const Str255 insertStr,short offset)	//does an 'insert before'
{
register short	start,insertLen=insertStr[0];
register short	len=s[0];

	if (insertLen > 0)
	{
		if (offset <= 0)						//insert at 'offset' chars from end of s
		{
			start = len + offset + 1;
			if (start < 1) start = 1;			//underflow - prefix		
		}	
		else									//insert at 'offset' chars from start of s
		{
			if (offset > len) offset = len + 1;	//overflow - suffix
			start = offset;				
		}
		if (start <= len) BlockMove((Ptr) &s[start],(Ptr) &s[start+insertLen],len-start+1);	//make room for insertStr
		BlockMove((Ptr) &insertStr[1],(Ptr) &s[start],insertLen); 							//copy inserStr into s
		s[0]+=insertLen;
	}
}

short myFindFirstInPStr(const Str255 s,unsigned char c)
{
	register short	i	=1;
	register short	len	=s[0];
	
	while ((i <= len) && (s[i] != c)) i++;
	return ((i > len) ? 0 : i);
}

void myDeleteElementFromPStr(Str255 s,unsigned short index)
{
register unsigned short		i,len = s[0];

	if (index <= len)
	{
		for (i = index; i < len; i++) s[i] = s[i + 1];
		s[0]--;
	}
}

void myReplaceCharWithPStrInPStr(Str255 s, unsigned char c, const Str255 insertStr) {
    short offset;
    
    if (myFindFirstInPStr(insertStr, c)) {
        return;
    }
    
    while (offset = myFindFirstInPStr(s, c)) {
        myDeleteElementFromPStr(s, offset);
        myInsertInPStr(s, insertStr, offset);
    }
}
