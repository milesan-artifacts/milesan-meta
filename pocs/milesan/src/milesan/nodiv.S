#include "memcfg.h"
#include "data.h"
.text
    li s0, REGDUMP_ADDR
    li a2, UDATA
    lw a0, 0(a2) #1
    lw a1, 8(a2) #0ffffffe6
    lw a2, 16(a2) #1
    lw a3, 24(a2) #c01f

    addi a2, a2, 0x1
    
    END:
    li s0, STOPSIG_ADDR
    fence
    sw a0, 0(s0)
    fence
	j END
