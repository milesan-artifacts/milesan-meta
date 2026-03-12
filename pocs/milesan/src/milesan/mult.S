#include "memcfg.h"
#include "data.h"
.text
    li s0, REGDUMP_ADDR
    li a2, UDATA
    lw a0, 0(a2) #1
    lw a1, 8(a2) #0ffffffe6
    lw a2, 16(a2) #1
    lw a3, 24(a2) #c01f

    mul ra, a1, a0
    sw ra, 0(s0)
    fence
  
    lui ra, 0x0 
    sw ra, 0(s0)
    fence
#    div ra, a2, a1
#    sw ra, 0(s0)
#    fence
#    
#    mul ra, a3, a1
#    sw ra, 0(s0)
#    fence
#
#    mul ra, ra, a1
#    sw ra, 0(s0)
#    fence

#    remu ra, s1, zero
#    sw ra, 0(s0)
#    fence
#
#    mulh ra, a1, a0
#    sw ra, 0(s0)
#    fence

#    mulh ra, a0, a2
#    sw ra, 0(s0)
#    fence

    END:
    li s0, STOPSIG_ADDR
    fence
    sw a0, 0(s0)
    fence
	j END
