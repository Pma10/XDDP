#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "parse.h"

static void basic(unsigned char *b) {
    memset(b,0,256); b[12]=8; b[14]=0x45; b[17]=40; b[23]=6;
    b[30]=192; b[31]=0; b[32]=2; b[33]=1;
    b[36]=0x63; b[37]=0xdd; b[46]=0x50; b[47]=0x10;
}
int main(void) {
    unsigned char b[256]; struct packet p;
    basic(b); memset(&p,0,sizeof(p));
    assert(parse_ip(b,b+54,&p)==0); assert(parse_transport(b,b+54,&p)==0);
    assert(p.port==25565 && p.flags==0x10);
    for (int size=0; size<54; size++) {
        memset(&p,0,sizeof(p));
        assert(parse_ip(b,b+size,&p)<0);
    }
    basic(b); b[14]=0x44; memset(&p,0,sizeof(p)); assert(parse_ip(b,b+54,&p)==-R_MALFORMED_IPV4);
    basic(b); b[46]=0x40; memset(&p,0,sizeof(p)); assert(!parse_ip(b,b+54,&p)); assert(parse_transport(b,b+54,&p)==-R_INVALID_TCP);
    basic(b); b[47]=3; memset(&p,0,sizeof(p)); assert(!parse_ip(b,b+54,&p)); assert(parse_transport(b,b+54,&p)==-R_INVALID_TCP);
    basic(b); b[20]=0x20; memset(&p,0,sizeof(p)); assert(!parse_ip(b,b+54,&p)); assert(p.fragment); assert(parse_transport(b,b+54,&p)==1);
    /* Deterministic mutation sweep under ASan/UBSan, including all truncation lengths. */
    for (int byte=0; byte<80; byte++) for (int value=0; value<256; value++) {
        basic(b); b[byte]=value;
        for (int size=0; size<80; size++) {
            memset(&p,0,sizeof(p));
            if (!parse_ip(b,b+size,&p)) (void)parse_transport(b,b+size,&p);
        }
    }
    puts("parser: valid, malformed, fragments and mutation/truncation sweep passed");
}
