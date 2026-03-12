from abc import ABC
import json

from milesan.util import IntRegIndivState
from rv.csrids import CSR_IDS, CSR_TYPES, CSRTypeEnum
from rv.csrids import SSTATUS_MASK, MSTATUS_MASK, MSTATUS_START_VAL, SSTATUS_START_VAL
from params.runparams import PRINT_CHECK_REGS_TAINT, CHECK_REGS_TAINT_PRECISE, PRINT_CHECK_REGS_TAINT_MISMATCH_OK, DO_ASSERT, IGNORE_SPIKE_OFFSET_IN_REG_CHECK
from params.fuzzparams import ALLOW_CSR_TAINT

INTREG_ABINAMES = [
    'zero', 'ra', 'sp', 'gp', 'tp', 't0', 't1', 't2', 's0', 's1', 'a0', 'a1', 'a2', 'a3', 'a4', 'a5', 'a6', 'a7', 's2', 's3', 's4', 's5', 's6', 's7', 's8', 's9', 's10', 's11', 't3', 't4', 't5', 't6'
]

FPREG_ABINAMES = [
    'ft0', 'ft1', 'ft2', 'ft3', 'ft4', 'ft5', 'ft6', 'ft7', 'fs0', 'fs1', 'fa0', 'fa1', 'fa2', 'fa3', 'fa4', 'fa5', 'fa6', 'fa7', 'fs2', 'fs3', 'fs4', 'fs5', 'fs6', 'fs7', 'fs8', 'fs9', 'fs10', 'fs11', 'ft8', 'ft9', 'ft10', 'ft11'
]

MAX_32b = 0xFFFFFFFF
MAX_64b = 0xFFFFFFFFFFFFFFFF
MAX_20b = 0xFFFFF
MAX_12b = 0xFFF

class __Register(ABC):
    def __init__(self,id: int = None, is_design_64bit: bool = False, val: int = 0, val_taint: int = 0, pickable: bool = False):
        self.id = id
        self.is_design_64bit = is_design_64bit
        self.mask = MAX_64b if is_design_64bit else MAX_32b
        self.n_bits = 64 if is_design_64bit else 32
        self.val = val&self.mask
        self.val_taint = val_taint&self.mask
        self.pickable = pickable

    def set_val(self, val):
        if(self.id != 0):
            self.val = val&self.mask
        # print(f"Setting {INTREG_ABINAMES[self.id]} to {hex(self.val)}")

    def set_val_taint(self, val_taint):
        if(self.id != 0):
            self.val_taint = val_taint&self.mask

    def get_val(self):
        return self.val

    def get_val_taint(self):
        return self.val_taint

    def reset(self):
        self.val = 0
        self.val_taint = 0

# TODO: extend this to allow field masks if necessary.
def _get_writeable_csr_value(value: int, csr_mask: int, csr_type: CSRTypeEnum):
    if csr_type == CSRTypeEnum.WLRL:
        return value&csr_mask # we only write the bits that can be written legally
    elif csr_type == CSRTypeEnum.WARL:
        return value&csr_mask # we only write the bits that can be written legally
    elif csr_type == CSRTypeEnum.WPRI:
        raise NotImplementedError("WPRI not implemented yet.")
    else:
        raise TypeError

class CSR(__Register):
    def __init__(self, csrfile, id: CSR_IDS, csr_mask, csr_type: CSRTypeEnum, val: int = 0, val_taint: int = 0):
        super().__init__(id, True, val, val_taint) # CSRs are always 64bit
        if DO_ASSERT:
            assert csr_type == CSRTypeEnum.WLRL or id == CSR_IDS.MEDELEG and csr_type == CSRTypeEnum.WARL, f"Only medeleg supported for other type than WLRL."
            assert csr_mask is not None, f"Got None as csr mask for {id.name}. Check if medeleg was profiled."
        self.csrfile = csrfile
        self.abi_name = id.name
        self.val = val
        self.val_taint = val_taint
        self.csr_mask = csr_mask
        self.csr_type = csr_type
        self.unreliable = False # Used for e.g. SEPC/SCAUSE, when the order of exception handling is not strictly determined by the spec and thus the value is ambiguous until overwritten.

    def set_val(self, val):
        self.val = self.mask&_get_writeable_csr_value(val,self.csr_mask,self.csr_type)
        # if self.id == CSR_IDS.MCAUSE:
        #     print(f"Setting {self.abi_name} to {hex(self.val)} ({hex(val)})")

    def set_val_taint(self, val_taint):
        from common.exceptions import TaintedCSRException

        if not ALLOW_CSR_TAINT and val_taint:
            raise TaintedCSRException(self.id, self.abi_name)
        self.val_taint = val_taint&self.mask

    def get_val(self):
        return self.val

    def get_val_taint(self):
        from common.exceptions import TaintedCSRException

        if not ALLOW_CSR_TAINT and self.val_taint:
            raise TaintedCSRException(self.id, self.abi_name)
        return self.val_taint

    def reset(self):
        self.set_val(0)
        self.set_val_taint(0)

# SSTATUS is a subset from MSTATUS so we need special classes for them.
class SStatus_CSR(CSR):
    def __init__(self, csrfile, val: int = 0, val_taint: int = 0):
        super().__init__(csrfile,CSR_IDS.SSTATUS,csrfile.csr_masks[CSR_IDS.SSTATUS],CSR_TYPES[CSR_IDS.MSTATUS], val, val_taint)
    
    def set_val(self, val):
        super().set_val(val)
        assert self.val&~(SSTATUS_START_VAL | SSTATUS_MASK) == 0 
        mstatus = self.csrfile.regs[CSR_IDS.MSTATUS].get_val()
        mstatus &= ~(SSTATUS_MASK & MAX_64b) # clear the bits
        mstatus |= (SSTATUS_MASK & self.val)
        self.csrfile.regs[CSR_IDS.MSTATUS].val = mstatus  # dont use setter here

class MStatus_CSR(CSR):
    def __init__(self, csrfile, val: int = 0, val_taint: int = 0):
        super().__init__(csrfile,CSR_IDS.MSTATUS,csrfile.csr_masks[CSR_IDS.MSTATUS],CSR_TYPES[CSR_IDS.MSTATUS], val, val_taint)

    def set_val(self, val):
        super().set_val(val)
        assert self.val&~(MSTATUS_START_VAL | MSTATUS_MASK) == 0 
        sstatus = self.csrfile.regs[CSR_IDS.SSTATUS].get_val()
        sstatus &= ~(SSTATUS_MASK & MAX_64b) # clear the bits
        sstatus |= (SSTATUS_MASK & self.val)
        self.csrfile.regs[CSR_IDS.SSTATUS].val = sstatus # dont use setter here

class Medeleg_CSR(CSR):
    def __init__(self, csrfile, val: int = 0, val_taint: int = 0):
        super().__init__(csrfile,CSR_IDS.MEDELEG,csrfile.csr_masks[CSR_IDS.MEDELEG],CSR_TYPES[CSR_IDS.MEDELEG], val, val_taint)
    

class CheckableRegister(__Register):
    def __init__(self, id: int, abi_name: str,is_design_64bit: bool, val: int = 0, val_taint: int = 0, pickable: bool = False):
        super().__init__(id, is_design_64bit, val, val_taint, pickable)
        self.abi_name = abi_name
    
    def check(self, cmp_val):
        cmp_val &= self.mask
        mismatch = self.val != cmp_val
            
        if not mismatch:
            return False
        else:
            return self.abi_name,self.val,cmp_val

    def check_taint(self, cmp_val, precise = CHECK_REGS_TAINT_PRECISE):
        cmp_val &= self.mask
        mismatch = self.val_taint != cmp_val
        if not precise:
            cover = ~self.val_taint&cmp_val == 0 # overapproximates, check if spike taint is covered by milesan sim taint
            if cover:
                if mismatch and PRINT_CHECK_REGS_TAINT_MISMATCH_OK:
                    print(f"\tTaint mismatch OK: {hex(self.val_taint)} covers {hex(cmp_val)}.")
                return False

        if not mismatch:
            return False
        else:
            return self.abi_name,self.val_taint,cmp_val

    def print_and_compare(self,rtl_val,rtl_val_taint):
        if self.is_design_64bit:
            if rtl_val == self.val:
                val_str =  "0x{:016x}".format(self.val)
            else:
                val_str = "0x{:016x} != 0x{:016x}".format(self.val,rtl_val)

            if rtl_val_taint == self.val_taint:
                val_taint_str = "0x{:016x}".format(self.val_taint)
            elif rtl_val_taint&~self.val_taint == 0:
                val_taint_str = "0x{:016x} >= 0x{:016x}".format(self.val_taint,rtl_val_taint)
            else:
                val_taint_str = "0x{:016x} != 0x{:016x}".format(self.val_taint,rtl_val_taint)

        else:
            if rtl_val == self.val:
                val_str =  "0x{:08x}".format(self.val)
            else:
                val_str = "0x{:08x} != 0x{:08x}".format(self.val,rtl_val)

            if rtl_val_taint == self.val_taint:
                val_taint_str = "0x{:08x}".format(self.val_taint)
            elif rtl_val_taint&~self.val_taint == 0:
                val_taint_str = "0x{:08x} >= 0x{:08x}".format(self.val_taint,rtl_val_taint)
            else:
                val_taint_str = "0x{:08x} != 0x{:08x}".format(self.val_taint,rtl_val_taint)
            
        row = [self.abi_name,val_str,val_taint_str]
        print("{: >30} {: >30} {: >30}".format(*row))

    def print(self):
        row = [self.abi_name,hex(self.val),hex(self.val_taint), self.fsm_state.name, "True" if self.pickable else "False"]
        print("{: >20} {: >20} {: >20} {: >20} {: >20}".format(*row))

class IntRegister(CheckableRegister):
    def __init__(self, id: int, is_design_64bit: bool, val: int = 0, val_taint: int = 0, pickable: bool = False):
        super().__init__(id, INTREG_ABINAMES[id], is_design_64bit, val, val_taint, pickable)
        self.fsm_state = IntRegIndivState.FREE

    def set_fsm_sate(self,new_state: IntRegIndivState = None):
        self.fsm_state = new_state

    def reset(self):
        super().reset()
        self.fsm_state = IntRegIndivState.FREE

   


