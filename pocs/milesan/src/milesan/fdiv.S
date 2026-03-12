#include "memcfg.h"
#include "data.h"
.text
    li s0, REGDUMP_ADDR
    li a2, UDATA
    lw a0, 0(a2) #b
    lw a1, 8(a2) #0ffffffe6
    lui t0, 0b10
    csrrw zero, mstatus, t0
    fcvt.s.w f0, a0
#    fcvt.s.w f1, a1
#    lw a2, 16(a2) #1
#    lw a3, 24(a2) #c01f

    fdiv.s f0, f1, f0
    fcvt.w.s ra, f0
    fsw f0, 0(s0)
    fence

     
    sw a0, 0(s0)
    fence

    sw a0, 0(s0)
    fence
    sw a0, 0(s0)
    fence
    END:
    li s0, STOPSIG_ADDR
    fence
    sw s0, 0(s0)
    fence
	j END
