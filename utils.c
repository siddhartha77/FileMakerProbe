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