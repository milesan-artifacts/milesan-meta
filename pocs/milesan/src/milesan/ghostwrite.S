#include "memcfg.h"
#include "data.h"
.text
li s0, REGDUMP_ADDR
la t0, UDATA
li a0, 0xfe
#vsetvli zero, zero, e8, m1
#vmv.v.x v0, a0
lw a0, 0(t0) #1
END:
li s0, STOPSIG_ADDR
fence
sw a0, 0(s0)
fence
j END
