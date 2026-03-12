#include "memcfg.h"
#include "data.h"
.text
    li s0, REGDUMP_ADDR
    li a2, UDATA
    lw a0, 0(a2) #b
    lw a1, 8(a2) #0ffffffe6
    lw a3, 24(a2) #c01f
    lw a2, 16(a2) #1

    
#    mul ra, a3, a0
#    sw ra, 0(s0)
#    fence
#
#    mul ra, ra, a0
#    sw ra, 0(s0)
#    fence

    div ra, a1, a0
    sw ra, 0(s0)
    
    divu ra, ra, a0
    sw ra, 0(s0)

#    mul ra, ra, a0
#    sw ra, 0(s0)
#
#    div ra, a3, a0
#    sw ra, 0(s0)
#
#    mulh ra, ra, a0
#    sw ra, 0(s0)
#    fence
#    remu ra, s1, zero
#    sw ra, 0(s0)
#    fence

#    mulh ra, a1, zero
#    sw ra, 0(s0)
#    fence
#
#    mulh ra, a0, zero
#    sw ra, 0(s0)
#    fence

    END:
    li s0, STOPSIG_ADDR
    fence
    sw s0, 0(s0)
    fence
	j END
