from params.fuzzparams import TAINT_EN, USE_MMU, USE_SPIKE_INTERM_ELF, RELOCATOR_REGISTER_ID, RDEP_MASK_REGISTER_ID, RDEP_MASK_REGISTER_ID_VIRT, RPROD_MASK_REGISTER_ID
from params.runparams import PRINT_CHECK_REGS, PRINT_CHECK_REGS_TAINT, PRINT_COLOR_TAINT, PRINT_FILTERED_REG_TRACEBACK, DO_ASSERT, PRINT_WRITEBACK_TAINT, PRINT_WRITEBACK, DUMP_WRITEBACK, DUMP_WRITEBACK_TAINT, ASSERT_WRITEBACK_TRACE
from rv.csrids import CSR_IDS, CSR_ABI_NAMES
from rv.util import INSTRUCTION_IDS, PARAM_SIZES_BITS_32, PARAM_SIZES_BITS_64, PARAM_IS_SIGNED
from rv.asmutil import li_into_reg, to_unsigned, INSTR_FUNCS_TAINT, INSTR_FUNCS
from rv.rv32i import rv32i_addi
from common.exceptions import TaintedCFOperandException
from milesan.privilegestate import PrivilegeStateEnum
from milesan.mmu_utils import phys2virt, PAGE_ALIGNMENT_MASK
from milesan.randomize.pickbytecodetaints import OPCODE_FIELD_MASKS, OPCODE_FIELD_BITS
from milesan.cfinstructionclasses import (
    BaseInstruction,
    BranchInstruction,
    CSRImmInstruction,
    CSRRegInstruction,
    EPCWriterInstruction,
    GenericCSRWriterInstruction,
    ImmInstruction,
    ImmRdInstruction,
    IntLoadInstruction,
    IntStoreInstruction,
    JALInstruction,
    JALRInstruction,
    MisalignedMemInstruction,
    MstatusWriterInstruction,
    PlaceholderConsumerInstr,
    PlaceholderPreConsumerInstr,
    PlaceholderProducerInstr0,
    PlaceholderProducerInstr1,
    PrivilegeDescentInstruction,
    R12DInstruction,
    RawDataWord,
    RegImmInstruction,
    SimpleExceptionEncapsulator,
    SimpleIllegalInstruction,
    SpecialInstruction,
    TvecWriterInstruction,
    compute_reg_traceback,
    filter_reg_traceback,
    is_placeholder,
)
from milesan.util import ExceptionCauseVal
from milesan.registers import INTREG_ABINAMES
from params.toleratebugsparams import (
    TOLERATE_BOOM_BRANCH_TRANSIENT_WINDOW,
    TOLERATE_BOOM_BREAKPOINT_TRANSIENT_WINDOW,
    TOLERATE_BOOM_ENV_CALL_FROM_M_MODE_TRANSIENT_WINDOW,
    TOLERATE_BOOM_ENV_CALL_FROM_S_MODE_TRANSIENT_WINDOW,
    TOLERATE_BOOM_ENV_CALL_FROM_U_MODE_TRANSIENT_WINDOW,
    TOLERATE_BOOM_ILLEGAL_INSTRUCTION_TRANSIENT_WINDOW,
    TOLERATE_BOOM_INSTR_ACCESS_FAULT_TRANSIENT_WINDOW,
    TOLERATE_BOOM_INSTR_ADDR_MISALIGNED_TRANSIENT_WINDOW,
    TOLERATE_BOOM_JALR_TRANSIENT_WINDOW,
    TOLERATE_BOOM_JAL_TRANSIENT_WINDOW,
    TOLERATE_BOOM_LOAD_ACCESS_FAULT_TRANSIENT_WINDOW,
    TOLERATE_BOOM_LOAD_ADDR_MISALIGNED_TRANSIENT_WINDOW,
    TOLERATE_BOOM_LOAD_PAGE_FAULT_TRANSIENT_WINDOW,
    TOLERATE_BOOM_PRIVDESCENT_TRANSIENT_WINDOW,
    TOLERATE_BOOM_STORE_AMO_ACCESS_FAULT_TRANSIENT_WINDOW,
    TOLERATE_BOOM_STORE_AMO_ADDR_MISALIGNED_TRANSIENT_WINDOW,
    TOLERATE_BOOM_STORE_AMO_PAGE_FAULT_TRANSIENT_WINDOW,
    TOLERATE_CVA6_BRANCH_TRANSIENT_WINDOW,
    TOLERATE_CVA6_BREAKPOINT_TRANSIENT_WINDOW,
    TOLERATE_CVA6_ENV_CALL_FROM_M_MODE_TRANSIENT_WINDOW,
    TOLERATE_CVA6_ENV_CALL_FROM_S_MODE_TRANSIENT_WINDOW,
    TOLERATE_CVA6_ENV_CALL_FROM_U_MODE_TRANSIENT_WINDOW,
    TOLERATE_CVA6_ILLEGAL_INSTRUCTION_TRANSIENT_WINDOW,
    TOLERATE_CVA6_INSTR_ACCESS_FAULT_TRANSIENT_WINDOW,
    TOLERATE_CVA6_INSTR_ADDR_MISALIGNED_TRANSIENT_WINDOW,
    TOLERATE_CVA6_JALR_TRANSIENT_WINDOW,
    TOLERATE_CVA6_JAL_TRANSIENT_WINDOW,
    TOLERATE_CVA6_LOAD_ACCESS_FAULT_TRANSIENT_WINDOW,
    TOLERATE_CVA6_LOAD_ADDR_MISALIGNED_TRANSIENT_WINDOW,
    TOLERATE_CVA6_LOAD_PAGE_FAULT_TRANSIENT_WINDOW,
    TOLERATE_CVA6_PRIVDESCENT_TRANSIENT_WINDOW,
    TOLERATE_CVA6_STORE_AMO_ACCESS_FAULT_TRANSIENT_WINDOW,
    TOLERATE_CVA6_STORE_AMO_ADDR_MISALIGNED_TRANSIENT_WINDOW,
    TOLERATE_CVA6_STORE_AMO_PAGE_FAULT_TRANSIENT_WINDOW,
    TOLERATE_OPENC910_BRANCH_TRANSIENT_WINDOW,
    TOLERATE_OPENC910_BREAKPOINT_TRANSIENT_WINDOW,
    TOLERATE_OPENC910_ENV_CALL_FROM_M_MODE_TRANSIENT_WINDOW,
    TOLERATE_OPENC910_ENV_CALL_FROM_S_MODE_TRANSIENT_WINDOW,
    TOLERATE_OPENC910_ENV_CALL_FROM_U_MODE_TRANSIENT_WINDOW,
    TOLERATE_OPENC910_ILLEGAL_INSTRUCTION_TRANSIENT_WINDOW,
    TOLERATE_OPENC910_INSTR_ACCESS_FAULT_TRANSIENT_WINDOW,
    TOLERATE_OPENC910_INSTR_ADDR_MISALIGNED_TRANSIENT_WINDOW,
    TOLERATE_OPENC910_JALR_TRANSIENT_WINDOW,
    TOLERATE_OPENC910_JAL_TRANSIENT_WINDOW,
    TOLERATE_OPENC910_LOAD_ACCESS_FAULT_TRANSIENT_WINDOW,
    TOLERATE_OPENC910_LOAD_ADDR_MISALIGNED_TRANSIENT_WINDOW,
    TOLERATE_OPENC910_LOAD_PAGE_FAULT_TRANSIENT_WINDOW,
    TOLERATE_OPENC910_PRIVDESCENT_TRANSIENT_WINDOW,
    TOLERATE_OPENC910_STORE_AMO_ACCESS_FAULT_TRANSIENT_WINDOW,
    TOLERATE_OPENC910_STORE_AMO_ADDR_MISALIGNED_TRANSIENT_WINDOW,
    TOLERATE_OPENC910_STORE_AMO_PAGE_FAULT_TRANSIENT_WINDOW,
    TOLERATE_ROCKET_BRANCH_TRANSIENT_WINDOW,
    TOLERATE_ROCKET_BREAKPOINT_TRANSIENT_WINDOW,
    TOLERATE_ROCKET_ENV_CALL_FROM_M_MODE_TRANSIENT_WINDOW,
    TOLERATE_ROCKET_ENV_CALL_FROM_S_MODE_TRANSIENT_WINDOW,
    TOLERATE_ROCKET_ENV_CALL_FROM_U_MODE_TRANSIENT_WINDOW,
    TOLERATE_ROCKET_ILLEGAL_INSTRUCTION_TRANSIENT_WINDOW,
    TOLERATE_ROCKET_INSTR_ACCESS_FAULT_TRANSIENT_WINDOW,
    TOLERATE_ROCKET_INSTR_ADDR_MISALIGNED_TRANSIENT_WINDOW,
    TOLERATE_ROCKET_JALR_TRANSIENT_WINDOW,
    TOLERATE_ROCKET_JAL_TRANSIENT_WINDOW,
    TOLERATE_ROCKET_LOAD_ACCESS_FAULT_TRANSIENT_WINDOW,
    TOLERATE_ROCKET_LOAD_ADDR_MISALIGNED_TRANSIENT_WINDOW,
    TOLERATE_ROCKET_LOAD_PAGE_FAULT_TRANSIENT_WINDOW,
    TOLERATE_ROCKET_PRIVDESCENT_TRANSIENT_WINDOW,
    TOLERATE_ROCKET_STORE_AMO_ACCESS_FAULT_TRANSIENT_WINDOW,
    TOLERATE_ROCKET_STORE_AMO_ADDR_MISALIGNED_TRANSIENT_WINDOW,
    TOLERATE_ROCKET_STORE_AMO_PAGE_FAULT_TRANSIENT_WINDOW,
)
from common.spike import SPIKE_STARTADDR
from common.exceptions import TaintedBranchException, TaintedJalrException, TaintedDDELIException, TaintedMemLoadException, TaintedMemStoreException
from milesan.registers import IntRegIndivState
import numpy as np
from rv.csrids import MPP_BIT, MIE_BIT, MPIE_BIT
from rv.csrids import SIE_BIT, SPIE_BIT, SPP_BIT
import subprocess
class Colorcodes(object):
    """
        Provides ANSI terminal color codes which are gathered via the ``tput``
        utility. That way, they are portable. If there occurs any error with
        ``tput``, all codes are initialized as an empty string.
        The provides fields are listed below.
        Control:
        - bold
        - reset
        Colors:
        - blue
        - green
        - orange
        - red
        :license: MIT
        """
    def __init__(self):
        try:
            self.bold = subprocess.check_output("tput bold".split(),text=True)
            self.reset = subprocess.check_output("tput sgr0".split(),text=True)
            self.blue = subprocess.check_output("tput setaf 4".split(),text=True)
            self.green = subprocess.check_output("tput setaf 2".split(),text=True)
            self.orange = subprocess.check_output("tput setaf 3".split(),text=True)
            self.red = subprocess.check_output("tput setaf 1".split(),text=True)
        except subprocess.CalledProcessError as e:
            
            self.bold = ""
            self.reset = ""
            self.blue = ""
            self.green = ""
            self.orange = ""
            self.red = ""

_c = Colorcodes()

CRED = _c.red
CEND = _c.reset

# Ensures that the register and its taint mask excludes some registers we don't want to get tainted
def clean_reg_taint(reg, reg_taint, skip_regs):
    for skip in skip_regs:
        if (reg^skip)&~reg_taint == 0: # untainted bits match
            # print(f"Untainted bits match: {hex(reg)} and {hex(skip)} with taint {hex(reg_taint)}")
            for i in range(5):
                reg_taint &= ~(1<<i)
                if (reg^skip)&~reg_taint != 0:
                    # print(f"Untainted bits dont match: {hex(reg)} and {hex(skip)} with taint {hex(reg_taint)}")
                    break
    return reg_taint

def is_tolerate_transient_window(fuzzerstate, instr: BaseInstruction):
    if "openc910" in fuzzerstate.design_name:
        if isinstance(instr, BranchInstruction):
            return TOLERATE_OPENC910_BRANCH_TRANSIENT_WINDOW
        elif isinstance(instr, JALRInstruction):
            return TOLERATE_OPENC910_JALR_TRANSIENT_WINDOW
        elif isinstance(instr, JALInstruction):
            return TOLERATE_OPENC910_JAL_TRANSIENT_WINDOW
        elif isinstance(instr, PrivilegeDescentInstruction):
            return TOLERATE_OPENC910_PRIVDESCENT_TRANSIENT_WINDOW
        elif isinstance(instr, SimpleExceptionEncapsulator):
            if instr.exception_op_type == ExceptionCauseVal.ID_INSTR_ADDR_MISALIGNED:
                return TOLERATE_OPENC910_INSTR_ADDR_MISALIGNED_TRANSIENT_WINDOW
            elif instr.exception_op_type == ExceptionCauseVal.ID_INSTR_ACCESS_FAULT:
                return TOLERATE_OPENC910_INSTR_ACCESS_FAULT_TRANSIENT_WINDOW
            elif instr.exception_op_type == ExceptionCauseVal.ID_ILLEGAL_INSTRUCTION:
                return TOLERATE_OPENC910_ILLEGAL_INSTRUCTION_TRANSIENT_WINDOW
            elif instr.exception_op_type == ExceptionCauseVal.ID_BREAKPOINT:
                return TOLERATE_OPENC910_BREAKPOINT_TRANSIENT_WINDOW
            elif instr.exception_op_type == ExceptionCauseVal.ID_LOAD_ADDR_MISALIGNED:
                return TOLERATE_OPENC910_LOAD_ADDR_MISALIGNED_TRANSIENT_WINDOW
            elif instr.exception_op_type == ExceptionCauseVal.ID_LOAD_ACCESS_FAULT:
                return TOLERATE_OPENC910_LOAD_ACCESS_FAULT_TRANSIENT_WINDOW
            elif instr.exception_op_type == ExceptionCauseVal.ID_STORE_AMO_ADDR_MISALIGNED:
                return TOLERATE_OPENC910_STORE_AMO_ADDR_MISALIGNED_TRANSIENT_WINDOW
            elif instr.exception_op_type == ExceptionCauseVal.ID_STORE_AMO_ACCESS_FAULT:
                return TOLERATE_OPENC910_STORE_AMO_ACCESS_FAULT_TRANSIENT_WINDOW    
            elif instr.exception_op_type == ExceptionCauseVal.ID_ENVIRONMENT_CALL_FROM_U_MODE:
                return TOLERATE_OPENC910_ENV_CALL_FROM_U_MODE_TRANSIENT_WINDOW
            elif instr.exception_op_type == ExceptionCauseVal.ID_ENVIRONMENT_CALL_FROM_S_MODE:
                return TOLERATE_OPENC910_ENV_CALL_FROM_S_MODE_TRANSIENT_WINDOW
            elif instr.exception_op_type == ExceptionCauseVal.ID_ENVIRONMENT_CALL_FROM_M_MODE:
                return TOLERATE_OPENC910_ENV_CALL_FROM_M_MODE_TRANSIENT_WINDOW
            elif instr.exception_op_type == ExceptionCauseVal.ID_LOAD_PAGE_FAULT:
                return TOLERATE_OPENC910_LOAD_PAGE_FAULT_TRANSIENT_WINDOW
            elif instr.exception_op_type == ExceptionCauseVal.ID_STORE_AMO_PAGE_FAULT:
                return TOLERATE_OPENC910_STORE_AMO_PAGE_FAULT_TRANSIENT_WINDOW
            else:
                assert False, f"{instr.get_str()} should not be used here"
            
    elif "cva6" in fuzzerstate.design_name:
        if isinstance(instr, BranchInstruction):
            return TOLERATE_CVA6_BRANCH_TRANSIENT_WINDOW
        elif isinstance(instr, JALRInstruction):
            return TOLERATE_CVA6_JALR_TRANSIENT_WINDOW
        elif isinstance(instr, JALInstruction):
            return TOLERATE_CVA6_JAL_TRANSIENT_WINDOW
        elif isinstance(instr, PrivilegeDescentInstruction):
            return TOLERATE_CVA6_PRIVDESCENT_TRANSIENT_WINDOW
        elif isinstance(instr, SimpleExceptionEncapsulator):
            if instr.exception_op_type == ExceptionCauseVal.ID_INSTR_ADDR_MISALIGNED:
                return TOLERATE_CVA6_INSTR_ADDR_MISALIGNED_TRANSIENT_WINDOW
            elif instr.exception_op_type == ExceptionCauseVal.ID_INSTR_ACCESS_FAULT:
                return TOLERATE_CVA6_INSTR_ACCESS_FAULT_TRANSIENT_WINDOW
            elif instr.exception_op_type == ExceptionCauseVal.ID_ILLEGAL_INSTRUCTION:
                return TOLERATE_CVA6_ILLEGAL_INSTRUCTION_TRANSIENT_WINDOW
            elif instr.exception_op_type == ExceptionCauseVal.ID_BREAKPOINT:
                return TOLERATE_CVA6_BREAKPOINT_TRANSIENT_WINDOW
            elif instr.exception_op_type == ExceptionCauseVal.ID_LOAD_ADDR_MISALIGNED:
                return TOLERATE_CVA6_LOAD_ADDR_MISALIGNED_TRANSIENT_WINDOW
            elif instr.exception_op_type == ExceptionCauseVal.ID_LOAD_ACCESS_FAULT:
                return TOLERATE_CVA6_LOAD_ACCESS_FAULT_TRANSIENT_WINDOW
            elif instr.exception_op_type == ExceptionCauseVal.ID_STORE_AMO_ADDR_MISALIGNED:
                return TOLERATE_CVA6_STORE_AMO_ADDR_MISALIGNED_TRANSIENT_WINDOW
            elif instr.exception_op_type == ExceptionCauseVal.ID_STORE_AMO_ACCESS_FAULT:
                return TOLERATE_CVA6_STORE_AMO_ACCESS_FAULT_TRANSIENT_WINDOW    
            elif instr.exception_op_type == ExceptionCauseVal.ID_ENVIRONMENT_CALL_FROM_U_MODE:
                return TOLERATE_CVA6_ENV_CALL_FROM_U_MODE_TRANSIENT_WINDOW
            elif instr.exception_op_type == ExceptionCauseVal.ID_ENVIRONMENT_CALL_FROM_S_MODE:
                return TOLERATE_CVA6_ENV_CALL_FROM_S_MODE_TRANSIENT_WINDOW
            elif instr.exception_op_type == ExceptionCauseVal.ID_ENVIRONMENT_CALL_FROM_M_MODE:
                return TOLERATE_CVA6_ENV_CALL_FROM_M_MODE_TRANSIENT_WINDOW
            elif instr.exception_op_type == ExceptionCauseVal.ID_LOAD_PAGE_FAULT:
                return TOLERATE_CVA6_LOAD_PAGE_FAULT_TRANSIENT_WINDOW
            elif instr.exception_op_type == ExceptionCauseVal.ID_STORE_AMO_PAGE_FAULT:
                return TOLERATE_CVA6_STORE_AMO_PAGE_FAULT_TRANSIENT_WINDOW
            else:
                assert False, f"{instr.get_str()} should not be used here"
            


    elif "boom" in fuzzerstate.design_name:
        if isinstance(instr, BranchInstruction):
            return TOLERATE_BOOM_BRANCH_TRANSIENT_WINDOW
        elif isinstance(instr, JALRInstruction):
            return TOLERATE_BOOM_JALR_TRANSIENT_WINDOW
        elif isinstance(instr, JALInstruction):
            return TOLERATE_BOOM_JAL_TRANSIENT_WINDOW
        elif isinstance(instr, PrivilegeDescentInstruction):
            return TOLERATE_BOOM_PRIVDESCENT_TRANSIENT_WINDOW
        elif isinstance(instr, SimpleExceptionEncapsulator):
            if instr.exception_op_type == ExceptionCauseVal.ID_INSTR_ADDR_MISALIGNED:
                return TOLERATE_BOOM_INSTR_ADDR_MISALIGNED_TRANSIENT_WINDOW
            elif instr.exception_op_type == ExceptionCauseVal.ID_INSTR_ACCESS_FAULT:
                return TOLERATE_BOOM_INSTR_ACCESS_FAULT_TRANSIENT_WINDOW
            elif instr.exception_op_type == ExceptionCauseVal.ID_ILLEGAL_INSTRUCTION:
                return TOLERATE_BOOM_ILLEGAL_INSTRUCTION_TRANSIENT_WINDOW
            elif instr.exception_op_type == ExceptionCauseVal.ID_BREAKPOINT:
                return TOLERATE_BOOM_BREAKPOINT_TRANSIENT_WINDOW
            elif instr.exception_op_type == ExceptionCauseVal.ID_LOAD_ADDR_MISALIGNED:
                return TOLERATE_BOOM_LOAD_ADDR_MISALIGNED_TRANSIENT_WINDOW
            elif instr.exception_op_type == ExceptionCauseVal.ID_LOAD_ACCESS_FAULT:
                return TOLERATE_BOOM_LOAD_ACCESS_FAULT_TRANSIENT_WINDOW
            elif instr.exception_op_type == ExceptionCauseVal.ID_STORE_AMO_ADDR_MISALIGNED:
                return TOLERATE_BOOM_STORE_AMO_ADDR_MISALIGNED_TRANSIENT_WINDOW
            elif instr.exception_op_type == ExceptionCauseVal.ID_STORE_AMO_ACCESS_FAULT:
                return TOLERATE_BOOM_STORE_AMO_ACCESS_FAULT_TRANSIENT_WINDOW    
            elif instr.exception_op_type == ExceptionCauseVal.ID_ENVIRONMENT_CALL_FROM_U_MODE:
                return TOLERATE_BOOM_ENV_CALL_FROM_U_MODE_TRANSIENT_WINDOW
            elif instr.exception_op_type == ExceptionCauseVal.ID_ENVIRONMENT_CALL_FROM_S_MODE:
                return TOLERATE_BOOM_ENV_CALL_FROM_S_MODE_TRANSIENT_WINDOW
            elif instr.exception_op_type == ExceptionCauseVal.ID_ENVIRONMENT_CALL_FROM_M_MODE:
                return TOLERATE_BOOM_ENV_CALL_FROM_M_MODE_TRANSIENT_WINDOW
            elif instr.exception_op_type == ExceptionCauseVal.ID_LOAD_PAGE_FAULT:
                return TOLERATE_BOOM_LOAD_PAGE_FAULT_TRANSIENT_WINDOW
            elif instr.exception_op_type == ExceptionCauseVal.ID_STORE_AMO_PAGE_FAULT:
                return TOLERATE_BOOM_STORE_AMO_PAGE_FAULT_TRANSIENT_WINDOW
            else:
                assert False, f"{instr.get_str()} should not be used here"
            

    elif "rocket" in fuzzerstate.design_name:
        if isinstance(instr, BranchInstruction):
            return TOLERATE_ROCKET_BRANCH_TRANSIENT_WINDOW
        elif isinstance(instr, JALRInstruction):
            return TOLERATE_ROCKET_JALR_TRANSIENT_WINDOW
        elif isinstance(instr, JALInstruction):
            return TOLERATE_ROCKET_JAL_TRANSIENT_WINDOW
        elif isinstance(instr, PrivilegeDescentInstruction):
            return TOLERATE_ROCKET_PRIVDESCENT_TRANSIENT_WINDOW
        elif isinstance(instr, SimpleExceptionEncapsulator):
            if instr.exception_op_type == ExceptionCauseVal.ID_INSTR_ADDR_MISALIGNED:
                return TOLERATE_ROCKET_INSTR_ADDR_MISALIGNED_TRANSIENT_WINDOW
            elif instr.exception_op_type == ExceptionCauseVal.ID_INSTR_ACCESS_FAULT:
                return TOLERATE_ROCKET_INSTR_ACCESS_FAULT_TRANSIENT_WINDOW
            elif instr.exception_op_type == ExceptionCauseVal.ID_ILLEGAL_INSTRUCTION:
                return TOLERATE_ROCKET_ILLEGAL_INSTRUCTION_TRANSIENT_WINDOW
            elif instr.exception_op_type == ExceptionCauseVal.ID_BREAKPOINT:
                return TOLERATE_ROCKET_BREAKPOINT_TRANSIENT_WINDOW
            elif instr.exception_op_type == ExceptionCauseVal.ID_LOAD_ADDR_MISALIGNED:
                return TOLERATE_ROCKET_LOAD_ADDR_MISALIGNED_TRANSIENT_WINDOW
            elif instr.exception_op_type == ExceptionCauseVal.ID_LOAD_ACCESS_FAULT:
                return TOLERATE_ROCKET_LOAD_ACCESS_FAULT_TRANSIENT_WINDOW
            elif instr.exception_op_type == ExceptionCauseVal.ID_STORE_AMO_ADDR_MISALIGNED:
                return TOLERATE_ROCKET_STORE_AMO_ADDR_MISALIGNED_TRANSIENT_WINDOW
            elif instr.exception_op_type == ExceptionCauseVal.ID_STORE_AMO_ACCESS_FAULT:
                return TOLERATE_ROCKET_STORE_AMO_ACCESS_FAULT_TRANSIENT_WINDOW    
            elif instr.exception_op_type == ExceptionCauseVal.ID_ENVIRONMENT_CALL_FROM_U_MODE:
                return TOLERATE_ROCKET_ENV_CALL_FROM_U_MODE_TRANSIENT_WINDOW
            elif instr.exception_op_type == ExceptionCauseVal.ID_ENVIRONMENT_CALL_FROM_S_MODE:
                return TOLERATE_ROCKET_ENV_CALL_FROM_S_MODE_TRANSIENT_WINDOW
            elif instr.exception_op_type == ExceptionCauseVal.ID_ENVIRONMENT_CALL_FROM_M_MODE:
                return TOLERATE_ROCKET_ENV_CALL_FROM_M_MODE_TRANSIENT_WINDOW
            elif instr.exception_op_type == ExceptionCauseVal.ID_LOAD_PAGE_FAULT:
                return TOLERATE_ROCKET_LOAD_PAGE_FAULT_TRANSIENT_WINDOW
            elif instr.exception_op_type == ExceptionCauseVal.ID_STORE_AMO_PAGE_FAULT:
                return TOLERATE_ROCKET_STORE_AMO_PAGE_FAULT_TRANSIENT_WINDOW
            else:
                assert False, f"{instr.get_str()} should not be used here"
            

        
    assert False, f"{instr.get_str()} should not be used here"
         
###
# Abstract classes with taint
###
class BaseInstruction_taint(BaseInstruction):
    instr_func_taint = None
    
    def __init__(self, fuzzerstate, instr_str):
        super().__init__(fuzzerstate, instr_str)

        self.instr_func_taint = INSTR_FUNCS_TAINT[self.instr_str]

    def check_regs_taint(self,reg_cmp):
        assert TAINT_EN
        for reg_id,reg_val in reg_cmp.items():
            if reg_id not in self.fuzzerstate.intregpickstate.regs:
                # print(f"{hex(self.addr)}: Ignoring register taint: {INTREG_ABINAMES[reg_id]}")
                continue
            if reg_val and PRINT_CHECK_REGS_TAINT:
                print(f"{hex(self.paddr)}: Checking register taint: {INTREG_ABINAMES[reg_id]}:{hex(reg_val)}")
            mismatch = self.fuzzerstate.intregpickstate.regs[reg_id].check_taint(reg_val)
            assert not mismatch, f"{hex(self.paddr)}: {self.instr_str}: Taint mismatch for {mismatch[0]}: {hex(mismatch[1])} != {hex(mismatch[2])}\n\t Traceback: {compute_reg_traceback(reg_id,self.paddr,self.fuzzerstate,reg_val).get_str()}"

    def execute_taint(self):
        assert TAINT_EN
        raise Exception(f"Function execute_taint() called on abstract class BaseInstruction_taint {self.get_str()}.")

    def inject_taint(self, is_spike_resolution: bool = True):
        self.set_bytecode(self.gen_bytecode_int(is_spike_resolution) ^ self.gen_bytecode_int_taint(is_spike_resolution))

class CFInstruction_taint(BaseInstruction_taint):
    def __init__(self, fuzzerstate, instr_str):
        super().__init__(fuzzerstate, instr_str)

class RDInstruction_taint(CFInstruction_taint):
    def __init__(self, fuzzerstate, instr_str):
        super().__init__(fuzzerstate, instr_str)
        self.rd_taint = 0
        self.writeback_trace = {"in-situ":(0,0), "final": (0,0)}
        self.rd_unreliable = False
    # This function writes back the tainted value to the destination register. Since the fields for the source and destination registers
    # could also be tainted, the alternative values for those executions (i.e. where the registers were chosen differently according to their taints)
    # are computed and written back to the set of registers derived from the taints in the rd field.
    def writeback_taint(self, res_taint, res, is_spike_resolution: bool):
        assert TAINT_EN
        assert self.rd_taint == 0
        if is_spike_resolution:
            self.rd_unreliable = self.fuzzerstate.intregpickstate.regs[self.rd].fsm_state != IntRegIndivState.FREE

        self.fuzzerstate.intregpickstate.regs[self.rd].set_val_taint(res_taint)
        if PRINT_WRITEBACK_TAINT:
            print(f"{self.get_str()} <- {hex(res_taint)}")
        if PRINT_WRITEBACK:
            print(f"{self.get_str()} <- {hex(res)}")
        self.add_writeback_trace(res, res_taint, is_spike_resolution)

    def add_writeback_trace(self, res, res_taint, is_spike_resolution: bool):
        if DO_ASSERT:
            assert res_taint == 0 or self.isdead or self.iscontext or (self.priv_level in self.fuzzerstate.taint_source_privs and self.va_layout in self.fuzzerstate.taint_source_layouts), f"{self.get_str()}: Taint detected in forbidden privelege or layout: allowed are {[p.name for p in self.fuzzerstate.taint_source_privs]} in layouts {self.fuzzerstate.taint_source_layouts}. Taint is {hex(res_taint)}"
        self.writeback_trace["in-situ" if is_spike_resolution else "final"] = (res, res_taint)
        if not is_spike_resolution and ASSERT_WRITEBACK_TRACE:
            self.assert_writeback_trace()

    def assert_writeback_trace(self): # This will fail when reducing.
        assert ASSERT_WRITEBACK_TRACE
        if not is_placeholder(self) and self.rd >0 and not self.rd_unreliable: # The placeholders will result in different values by construction.
            assert self.writeback_trace["in-situ"][0] == self.writeback_trace["final"][0], f"Writeback trace value mismatch between in-situ and final: {self.get_str()}: {hex(self.writeback_trace['in-situ'][0])} !=  {hex(self.writeback_trace['final'][0])}"
        assert self.writeback_trace["in-situ"][1] == self.writeback_trace["final"][1], f"Writeback trace taint mismatch between in-situ and final: {self.get_str()}: {hex(self.writeback_trace['in-situ'][1])} !=  {hex(self.writeback_trace['final'][1])}"


# does not inherit from ImmInstruction
class ImmInstruction_taint(CFInstruction_taint):
    imm_taint: int
    def __init__(self, fuzzerstate, instr_str):
        super().__init__(fuzzerstate, instr_str)
        self.imm_taint = 0x0

    def write_taint(self, is_spike_resolution: bool = False):
        if DO_ASSERT:
            assert self.paddr >= SPIKE_STARTADDR
            assert self.paddr < SPIKE_STARTADDR + self.fuzzerstate.memsize
            if self.imm_taint:
                self.fuzzerstate.memview.write_taint(self.paddr, self.gen_bytecode_int_taint(is_spike_resolution), 4)
        # if self.imm_taint:
        #     print(f"{self.get_str()} adds taint extra with imm {hex(self.imm_taint)}")
        # else:
        #     print(f"{self.get_str()} reduces taint.")

    def assert_imm_size(self):
        if DO_ASSERT:
            assert hasattr(self, 'imm')
            if self.fuzzerstate.is_design_64bit:
                curr_param_size = PARAM_SIZES_BITS_64[INSTRUCTION_IDS[self.instr_str]][-1]
            else:
                curr_param_size = PARAM_SIZES_BITS_32[INSTRUCTION_IDS[self.instr_str]][-1]
            if PARAM_IS_SIGNED[INSTRUCTION_IDS[self.instr_str]][-1]:
                assert self.imm >= -(1<<(curr_param_size-1)), f"{hex(self.imm)} not within paramsize: (signed, {curr_param_size})"
                assert self.imm <  1<<(curr_param_size-1),  f"{hex(self.imm)} not within paramsize: (signed, {curr_param_size})"
            else:
                assert self.imm >= 0
                assert self.imm <  1<<curr_param_size, f"{hex(self.imm)} not within paramsize: (unsigned, {curr_param_size})"


            assert hasattr(self, 'imm_taint')
            if self.fuzzerstate.is_design_64bit:
                curr_param_size = PARAM_SIZES_BITS_64[INSTRUCTION_IDS[self.instr_str]][-1]
            else:
                curr_param_size = PARAM_SIZES_BITS_32[INSTRUCTION_IDS[self.instr_str]][-1]
            if PARAM_IS_SIGNED[INSTRUCTION_IDS[self.instr_str]][-1]:
                assert self.imm_taint >= -(1<<(curr_param_size-1)), f"{hex(self.imm_taint)} not within paramsize: (signed, {curr_param_size})"
                assert self.imm_taint <  1<<(curr_param_size-1),  f"{hex(self.imm_taint)} not within paramsize: (signed, {curr_param_size})"
            else:
                assert self.imm_taint >= 0
                assert self.imm_taint <  1<<curr_param_size, f"{hex(self.imm_taint)} not within paramsize: (unsigned, {curr_param_size})"

###
# Concrete classes with taint: integers
###
class R12DInstruction_taint(R12DInstruction, RDInstruction_taint):
    def __init__(self, fuzzerstate, instr_str: str, rd: int, rs1: int, rs2: int, iscompressed: bool = False, is_rd_nonpickable_ok: bool = False):
        super().__init__(fuzzerstate, instr_str, rd, rs1, rs2, iscompressed, is_rd_nonpickable_ok)
        self.rs1_taint = 0
        self.rs2_taint = 0
        self.rd_taint = 0

    def execute_taint(self, res, is_spike_resolution: bool):
        from milesan.randomize.createcfinstr import is_tolerate_R12DInstruction
        assert TAINT_EN
        if self.paddr == -1:
            print(f"Skipping execution of {self.get_str()}")
            return
        assert self.instr_func_taint is not None, f"Cannot execute {self.get_str()}: no instr_func_taint found."
        assert self.fuzzerstate is not None, f"fuzzerstate not set, cannot execute {self.get_str()}" 
        rs1_val = self.fuzzerstate.intregpickstate.regs[self.rs1].get_val()
        rs2_val = self.fuzzerstate.intregpickstate.regs[self.rs2].get_val()
        rs1_val_taint = self.fuzzerstate.intregpickstate.regs[self.rs1].get_val_taint()
        rs2_val_taint = self.fuzzerstate.intregpickstate.regs[self.rs2].get_val_taint()
        if (rs1_val_taint or rs2_val_taint) and not is_tolerate_R12DInstruction(self.instr_str, self.fuzzerstate):
            raise TaintedDDELIException(
                                        fuzzerstate=self.fuzzerstate,
                                        reg_id = self.rs1 if rs1_val_taint else self.rs2,
                                        instr=self)
        # Compute the taint results of the operation.
        res_taint = self.instr_func_taint(rs1_val, rs1_val_taint, rs2_val, rs2_val_taint, self.fuzzerstate.is_design_64bit)
        # Compute alternative results if other soruce registers had been choosen.
        res_taint |= self.compute_alt_res_taint(res)
        # Writeback taints according to tainted bits in rd.
        self.writeback_taint(res_taint, res, is_spike_resolution)

    # Overrides function in R12DInstructionClass
    def execute(self, is_spike_resolution: bool = True):
        if self.paddr == -1:
            print(f"Skipping execution of {self.get_str()}")
            return
        assert self.instr_func is not None, f"Cannot execute {self.get_str()}: no instr_func found."
        assert self.fuzzerstate is not None, f"fuzzerstate not set, cannot execute {self.get_str()}" 
        if not is_spike_resolution:
            self.assert_addr()
            self.fuzzerstate.curr_pc += (2 if self.iscompressed else 4)
        rs1_val = self.fuzzerstate.intregpickstate.regs[self.rs1].get_val()
        rs2_val = self.fuzzerstate.intregpickstate.regs[self.rs2].get_val()
        res = self.instr_func(rs1_val,rs2_val, self.fuzzerstate.is_design_64bit)
        # Compute taint propagation before writing back result
        if TAINT_EN:
            self.execute_taint(res, is_spike_resolution)
        self.fuzzerstate.intregpickstate.regs[self.rd].set_val(res)
        self.fuzzerstate.advance_minstret()

    def compute_alt_res_taint(self, res):
        assert TAINT_EN
        res_taint = 0x0
        for alt_rs1_id, alt_rs1 in self.fuzzerstate.intregpickstate.regs.items():
            for alt_rs2_id, alt_rs2 in self.fuzzerstate.intregpickstate.regs.items():
                if ((alt_rs1_id^self.rs1)&(~self.rs1_taint) == 0 and self.rs1_taint != 0) and ((alt_rs2_id^self.rs2)&(~self.rs2_taint) == 0 and self.rs2_taint != 0) : # only differ in the tainted bits, therefore this register could have been used for addition instead and we need to derive the taints
                    print(f"{INTREG_ABINAMES[alt_rs1_id]} matches {INTREG_ABINAMES[self.rs1]} and {INTREG_ABINAMES[alt_rs2_id]} matches {INTREG_ABINAMES[self.rs2]} in untainted bits")
                    alt_res = self.instr_func(alt_rs1.get_val(),alt_rs2.get_val())
                    res_taint |= alt_res^res
        return res_taint


    def get_str(self, is_spike_resolution: bool = USE_SPIKE_INTERM_ELF, color_taint: bool= PRINT_COLOR_TAINT):
        if not color_taint:
            return super().get_str()
        if self.fuzzerstate.intregpickstate.regs[self.rd].get_val_taint():
            rd_str = CRED + INTREG_ABINAMES[self.rd] + CEND
        else:
            rd_str = INTREG_ABINAMES[self.rd]
        if self.fuzzerstate.intregpickstate.regs[self.rs1].get_val_taint():
            rs1_str = CRED + INTREG_ABINAMES[self.rs1] + CEND
        else:
            rs1_str = INTREG_ABINAMES[self.rs1]
        if self.fuzzerstate.intregpickstate.regs[self.rs2].get_val_taint():
            rs2_str = CRED + INTREG_ABINAMES[self.rs2] + CEND
        else:
            rs2_str = INTREG_ABINAMES[self.rs2]
        
        return f"{self.get_preamble()}: {self.instr_str} {rd_str}, {rs1_str}, {rs2_str}"

class ImmRdInstruction_taint(ImmRdInstruction, ImmInstruction_taint, RDInstruction_taint):
    def __init__(self, fuzzerstate, instr_str: str, rd: int, imm: int, imm_taint: int = 0, iscompressed: bool = False, is_rd_nonpickable_ok: bool = False):
        super().__init__(fuzzerstate, instr_str, rd, imm, iscompressed, is_rd_nonpickable_ok)
        self.rd_taint = 0       
        self.imm_taint = imm_taint

    def gen_bytecode_int_taint(self, is_spike_resolution: bool):
        assert TAINT_EN
        assert self.rd_taint == 0, "Tainting register selection bits not supported yet."
        rd = self.rd
        imm = self.imm
        self.rd = self.rd_taint # set regs to taints to get taint bytecode
        self.imm = self.imm_taint
        taint_bytecode = self.gen_bytecode_int(is_spike_resolution)
        self.rd = 0x00 # set regs to 0 to get taint bytecode mask to remove func and opcode fields
        self.imm = 0x00
        taint_bytecode_mask = self.gen_bytecode_int(is_spike_resolution)
        self.rd = rd
        self.imm = imm
        masked_taint = taint_bytecode ^ taint_bytecode_mask
        return masked_taint
 
    def compute_alt_res_taint(self, res):
        assert TAINT_EN
        return 0x0 # skip possible immediates for now

    def execute_taint(self, res, is_spike_resolution: bool):
        assert TAINT_EN
        # if is_spike_resolution:
        #     assert not (SPIKE_STARTADDR != self.fuzzerstate.design_base_addr and "auipc" in self.instr_str and self.fuzzerstate.intregpickstate.regs[self.rd].fsm_state == IntRegIndivState.FREE), f"{self.get_str()}: {SPIKE_STARTADDR} != {self.fuzzerstate.design_base_addr}, rd {INTREG_ABINAMES[self.rd]} is { self.fuzzerstate.intregpickstate.regs[self.rd].fsm_state.name}"

        # Compute the taint results of the operation. The address is never tainted.
        res_taint = self.instr_func_taint(self.paddr, 0x0, self.imm, self.imm_taint, self.fuzzerstate.is_design_64bit)
        # Compute alternative results if other soruce registers had been choosen.
        # res_taint |= self.compute_alt_res_taint(res)
        # Writeback taints according to tainted bits in rd.
        self.writeback_taint(res_taint, res, is_spike_resolution)

    def get_str(self, is_spike_resolution: bool = USE_SPIKE_INTERM_ELF, color_taint: bool = PRINT_COLOR_TAINT):
        if not color_taint or not self.imm_taint:
            return super().get_str()

        return f"{self.get_preamble()}: {self.instr_str} {INTREG_ABINAMES[self.rd]}," + CRED + f"{hex(self.imm)}" + CEND

    # Overrides function in ImmRdInstructionClass
    def execute(self, is_spike_resolution: bool = True):
        if not is_spike_resolution:
            self.assert_addr()
            self.fuzzerstate.curr_pc += (2 if self.iscompressed else 4)
        if USE_MMU:
            res = self.instr_func(self.vaddr, self.imm, self.fuzzerstate.is_design_64bit)
        else:
            res = self.instr_func(self.paddr, self.imm, self.fuzzerstate.is_design_64bit)
        if TAINT_EN:
            self.execute_taint(res, is_spike_resolution)
        self.fuzzerstate.intregpickstate.regs[self.rd].set_val(res)
        self.fuzzerstate.advance_minstret()

class RegImmInstruction_taint(RegImmInstruction, ImmInstruction_taint, RDInstruction_taint):
    def __init__(self, fuzzerstate, instr_str: str, rd: int, rs1: int, imm: int, imm_taint: int = 0, iscompressed: bool = False, is_rd_nonpickable_ok: bool = False):
        super().__init__(fuzzerstate, instr_str, rd, rs1, imm, iscompressed, is_rd_nonpickable_ok)
        self.rs1_taint = 0
        self.rd_taint = 0
        self.imm_taint = imm_taint

    def gen_bytecode_int_taint(self, is_spike_resolution: bool):
        assert TAINT_EN
        assert self.rs1_taint == 0 and self.rd_taint == 0, "Tainting register selection bits not supported yet."
        rd = self.rd
        rs1 = self.rs1
        imm = self.imm
        self.rd = self.rd_taint # set regs to taints to get taint bytecode
        self.rs1 = self.rs1_taint
        self.imm = self.imm_taint
        taint_bytecode = self.gen_bytecode_int(is_spike_resolution)
        self.rd = 0x00 # set regs to 0 to get taint bytecode mask to remove func and opcode fields
        self.rs1 = 0x00
        self.imm = 0x00
        taint_bytecode_mask = self.gen_bytecode_int(is_spike_resolution)
        self.rd = rd
        self.rs1 = rs1
        self.imm = imm
        masked_taint = taint_bytecode ^ taint_bytecode_mask
        return masked_taint

    def compute_alt_res_taint(self, res):
        assert TAINT_EN
        return 0x0 # skip possible immediates for now

    def execute_taint(self, res, is_spike_resolution: bool):
        assert TAINT_EN
        rs1_val = self.fuzzerstate.intregpickstate.regs[self.rs1].get_val()
        rs1_val_taint = self.fuzzerstate.intregpickstate.regs[self.rs1].get_val_taint()
        # Compute the taint results of the operation.
        res_taint = self.instr_func_taint(rs1_val, rs1_val_taint, self.imm, self.imm_taint, self.fuzzerstate.is_design_64bit)
        # Compute alternative results if other soruce registers had been choosen.
        res_taint |= self.compute_alt_res_taint(res)
        # Writeback taints according to tainted bits in rd.
        self.writeback_taint(res_taint, res, is_spike_resolution)

    def execute(self, is_spike_resolution: bool = True):
        if not is_spike_resolution:
            self.assert_addr()
            self.fuzzerstate.curr_pc += (2 if self.iscompressed else 4)
        rs1_val = self.fuzzerstate.intregpickstate.regs[self.rs1].get_val()
        res = self.instr_func(rs1_val, self.imm, self.fuzzerstate.is_design_64bit)
        if TAINT_EN:
            self.execute_taint(res, is_spike_resolution)
        self.fuzzerstate.intregpickstate.regs[self.rd].set_val(res)
        self.fuzzerstate.advance_minstret()


    def get_str(self, is_spike_resolution: bool = USE_SPIKE_INTERM_ELF, color_taint: bool= PRINT_COLOR_TAINT):
        if not color_taint:
            return super().get_str()
        if self.fuzzerstate.intregpickstate.regs[self.rd].get_val_taint():
            rd_str = CRED + INTREG_ABINAMES[self.rd] + CEND
        else:
            rd_str = INTREG_ABINAMES[self.rd]
        if self.fuzzerstate.intregpickstate.regs[self.rs1].get_val_taint():
            rs1_str = CRED + INTREG_ABINAMES[self.rs1] + CEND
        else:
            rs1_str = INTREG_ABINAMES[self.rs1]
        if self.imm_taint:
            imm_str = CRED + hex(self.imm) + CEND
        else:
            imm_str = hex(self.imm)
        
        return f"{self.get_preamble()}: {self.instr_str} {rd_str}, {rs1_str}, {imm_str}"



class JALInstruction_taint(JALInstruction, ImmInstruction_taint, RDInstruction_taint):
    def __init__(self, fuzzerstate, instr_str: str, rd: int, imm: int, iscompressed: bool = False):
        super().__init__(fuzzerstate, instr_str, rd, imm, iscompressed)
        self.rd_taint = 0

    def execute_taint(self, res, is_spike_resolution):
        assert TAINT_EN
        # We assume the PC does not get tainted, therefore the result of JAL is never either.
        self.writeback_taint(0x0, res, is_spike_resolution)

    def execute(self, is_spike_resolution: bool = True):
        if not is_spike_resolution:
            self.assert_addr()
            if USE_MMU:
                self.fuzzerstate.curr_pc = self.vaddr + self.imm
            else:
                self.fuzzerstate.curr_pc = self.paddr + self.imm
        if USE_MMU:
            res = self.instr_func(self.vaddr, 0x0, self.fuzzerstate.is_design_64bit)
        else:
            res = self.instr_func(self.paddr, 0x0, self.fuzzerstate.is_design_64bit)
        if TAINT_EN:
            self.execute_taint(res, is_spike_resolution)
        
        self.fuzzerstate.intregpickstate.regs[self.rd].set_val(res)
        self.fuzzerstate.advance_minstret()

    def blacklist_transient_window(self):
        next_trans_paddr = self.paddr+4 if not self.iscompressed else self.paddr+2
        if next_trans_paddr&PAGE_ALIGNMENT_MASK == self.paddr&PAGE_ALIGNMENT_MASK:
            self.fuzzerstate.blacklist_gadget_addr(next_trans_paddr,self.va_layout, self.priv_level)

class JALRInstruction_taint(JALRInstruction, ImmInstruction_taint, RDInstruction_taint):
    def __init__(self, fuzzerstate, instr_str: str, rd: int, rs1: int, imm: int, producer_id: int, to_new_layout: bool = False, iscompressed: bool = False):
        super().__init__(fuzzerstate, instr_str, rd, rs1, imm, producer_id, to_new_layout, iscompressed)
        self.rd_taint = 0
        self.rs1_taint = 0

    def execute_taint(self, res, is_spike_resolution: bool):
        assert TAINT_EN
        # assert self.fuzzerstate.intregpickstate.regs[self.rs1].get_val_taint() == 0, f"{self.get_str()}: source register is tainted. This is not allowed."
        if self.fuzzerstate.intregpickstate.regs[self.rs1].get_val_taint():
            raise TaintedCFOperandException(
                                        fuzzerstate=self.fuzzerstate,
                                        reg_id=self.rs1,
                                        instr=self)
        # We assume the PC does not get tainted, therefore the result of JAL is never either.
        self.writeback_taint(0x0, res, is_spike_resolution)

    def execute(self, is_spike_resolution: bool = True):
        if not is_spike_resolution:
            self.assert_addr()
            self.fuzzerstate.curr_pc = self.fuzzerstate.intregpickstate.regs[self.rs1].get_val() + self.imm
        if USE_MMU:
            res = self.instr_func(self.vaddr, 0x0, self.fuzzerstate.is_design_64bit)
        else:
            res = self.instr_func(self.paddr, 0x0, self.fuzzerstate.is_design_64bit)
        if TAINT_EN:
            self.execute_taint(res, is_spike_resolution)

        self.fuzzerstate.intregpickstate.regs[self.rd].set_val(res)
        self.fuzzerstate.advance_minstret()

    def blacklist_transient_window(self):
        next_trans_paddr = self.paddr+4 if not self.iscompressed else self.paddr+2
        if next_trans_paddr&PAGE_ALIGNMENT_MASK == self.paddr&PAGE_ALIGNMENT_MASK:
            self.fuzzerstate.blacklist_gadget_addr(next_trans_paddr,self.va_layout, self.priv_level)



## Extended Placeholder Instructions ##
class PlaceholderProducerInstr0_taint(PlaceholderProducerInstr0, RDInstruction_taint):
    def __init__(self, fuzzerstate, rd: int, producer_id: int):
        super().__init__(fuzzerstate, rd, producer_id)
        self.rd_taint = 0

    def execute_taint(self, res, is_spike_resolution: bool):
        assert TAINT_EN
        self.writeback_taint(0x0,res,is_spike_resolution)

    def execute(self, is_spike_resolution: bool = True):
        if is_spike_resolution:
            if self.spike_resolution_offset is None:
                if TAINT_EN:
                    self.execute_taint(0x0,is_spike_resolution)
                    self.fuzzerstate.advance_minstret()
                return
            else:
                spike_res_off = self.spike_resolution_offset
                if USE_MMU and self.fuzzerstate.is_design_64bit and self.produce_va_layout != -1: 
                    spike_res_off = (self.spike_resolution_offset | 0x80000000) & 0xffffffff # TODO double check if the check of the 64th bit is valid
                imm = li_into_reg(to_unsigned(spike_res_off, self.fuzzerstate.is_design_64bit), False)[0]
        else:
            assert self.rtl_offset is not None
            rtl_off = self.rtl_offset
            if USE_MMU and self.fuzzerstate.is_design_64bit and self.produce_va_layout != -1:
                rtl_off = (self.rtl_offset | 0x80000000) & 0xffffffff # TODO double check if the check of the 64th bit is valid
            self.assert_addr()
            self.fuzzerstate.curr_pc += (2 if self.iscompressed else 4)
            imm = li_into_reg(to_unsigned(rtl_off, self.fuzzerstate.is_design_64bit), False)[0]

        res = self.instr_func(None,imm,self.fuzzerstate.is_design_64bit)
        if TAINT_EN:
            self.execute_taint(res,is_spike_resolution)
        self.fuzzerstate.intregpickstate.regs[self.rd].set_val(res)
        self.fuzzerstate.advance_minstret()

   
class PlaceholderProducerInstr1_taint(PlaceholderProducerInstr1, RDInstruction_taint):
    def __init__(self, fuzzerstate, rd: int, producer_id: int):
        super().__init__(fuzzerstate, rd, producer_id)
        self.rd_taint = 0

    def execute_taint(self, res, is_spike_resolution: bool):
        assert TAINT_EN
        rd_taint = self.fuzzerstate.intregpickstate.regs[self.rd].get_val_taint()
        assert rd_taint == 0, "rd is tainted, this should not happen."
        self.writeback_taint(0x0,res,is_spike_resolution)

    def execute(self, is_spike_resolution: bool = True):
        if is_spike_resolution:
            if self.spike_resolution_offset is None:
                assert self.fuzzerstate.intregpickstate.regs[self.rd].get_val_taint() == 0
                if TAINT_EN:
                    self.execute_taint(0x0,is_spike_resolution)
                    self.fuzzerstate.advance_minstret()
                return
            else:
                spike_res_off = self.spike_resolution_offset
                if USE_MMU and self.fuzzerstate.is_design_64bit and self.produce_va_layout != -1:
                    spike_res_off = (self.spike_resolution_offset | 0x80000000) & 0xffffffff
                uimm = li_into_reg(to_unsigned(spike_res_off, self.fuzzerstate.is_design_64bit), False)[1]
        else:
            rtl_off = self.rtl_offset
            if USE_MMU and self.fuzzerstate.is_design_64bit and self.produce_va_layout != -1: 
                rtl_off = (self.rtl_offset | 0x80000000) & 0xffffffff # TODO double check if the check of the 64th bit is valid
            self.assert_addr()
            self.fuzzerstate.curr_pc += (2 if self.iscompressed else 4)
            uimm = li_into_reg(to_unsigned(rtl_off, self.fuzzerstate.is_design_64bit), False)[1]
        rd_val = self.fuzzerstate.intregpickstate.regs[self.rd].get_val()
        res = self.instr_func(rd_val, uimm, self.fuzzerstate.is_design_64bit)
        if TAINT_EN:
            self.execute_taint(res, is_spike_resolution)
        self.fuzzerstate.intregpickstate.regs[self.rd].set_val(res)
        self.fuzzerstate.advance_minstret()

# Does not inherit from RDInstruction_taint since it writes to rdep
class PlaceholderPreConsumerInstr_taint(PlaceholderPreConsumerInstr, BaseInstruction_taint):
    def __init__(self, fuzzerstate, rdep: int, producer_id: int, is_rprod: bool = False):
        super().__init__(fuzzerstate, rdep, producer_id, is_rprod)
        self.rdep_taint = 0
        self.writeback_trace = {"in-situ":0, "final": 0}

    def execute_taint(self, res, is_spike_resolution):
        assert TAINT_EN
        rdep_taint = self.fuzzerstate.intregpickstate.regs[self.rdep].get_val_taint()
        assert rdep_taint == 0, "rdep is tainted, this should not happen."
        if USE_MMU and self.fuzzerstate.is_design_64bit and self.is_rprod and self.produce_va_layout != -1:
            mask_taint = self.fuzzerstate.intregpickstate.regs[RPROD_MASK_REGISTER_ID].get_val_taint()
        elif USE_MMU and self.fuzzerstate.is_design_64bit and self.produce_va_layout != -1:
            mask_taint = self.fuzzerstate.intregpickstate.regs[RDEP_MASK_REGISTER_ID_VIRT].get_val_taint()
        else:
            mask_taint = self.fuzzerstate.intregpickstate.regs[RDEP_MASK_REGISTER_ID].get_val_taint()
        assert mask_taint == 0, "mask is tainted, this should not happen."
        self.writeback_taint(0, res, is_spike_resolution)

    def execute(self, is_spike_resolution: bool = True):
        if not is_spike_resolution:
            self.assert_addr()
            self.fuzzerstate.curr_pc += (2 if self.iscompressed else 4)
        rdep_val = self.fuzzerstate.intregpickstate.regs[self.rdep].get_val()
        if USE_MMU and self.fuzzerstate.is_design_64bit and self.is_rprod and self.produce_va_layout != -1:
            mask = self.fuzzerstate.intregpickstate.regs[RPROD_MASK_REGISTER_ID].get_val()
        elif USE_MMU and self.fuzzerstate.is_design_64bit and self.produce_va_layout != -1:
            mask = self.fuzzerstate.intregpickstate.regs[RDEP_MASK_REGISTER_ID_VIRT].get_val()
        else:
            mask = self.fuzzerstate.intregpickstate.regs[RDEP_MASK_REGISTER_ID].get_val()
        res = self.instr_func(rdep_val,mask,self.fuzzerstate.is_design_64bit)
        if TAINT_EN:
            self.execute_taint(res, is_spike_resolution)
        self.fuzzerstate.intregpickstate.regs[self.rdep].set_val(res)
        self.fuzzerstate.advance_minstret()

    # This function writes back the tainted value to the destination register which is the rdep for this class.
    # Since the fields for the source and destination registers could also be tainted, the alternative values for 
    # those executions (i.e. where the registers were chosen differently according to their taints)
    # are computed and written back to the set of registers derived from the taints in the rdep field.
    def writeback_taint(self, res_taint, res, is_spike_resolution):
        assert TAINT_EN
        assert self.rdep_taint == 0
        assert res_taint == 0
        self.fuzzerstate.intregpickstate.regs[self.rdep].set_val_taint(res_taint)
        if PRINT_WRITEBACK_TAINT:
            print(f"{self.get_str()} <- {hex(res_taint)}")
        if PRINT_WRITEBACK:
            print(f"{self.get_str()} <- {hex(res)}")
        self.add_writeback_trace(res_taint, is_spike_resolution)

    def add_writeback_trace(self, res_taint, is_spike_resolution: bool):
        assert res_taint == 0
        self.writeback_trace["in-situ" if is_spike_resolution else "final"] = res_taint
        if not is_spike_resolution:
            self.assert_writeback_trace()

    def assert_writeback_trace(self):
        assert self.writeback_trace["in-situ"] == self.writeback_trace["final"]

class PlaceholderConsumerInstr_taint(PlaceholderConsumerInstr, RDInstruction_taint):
    def __init__(self, fuzzerstate, rd: int, rdep: int, rprod: int, producer_id: int):
        super().__init__(fuzzerstate, rd, rdep, rprod, producer_id)
        self.rd_taint = 0
        self.rdep_taint = 0
        self.rprod_taint = 0

    def execute_taint(self, res, is_spike_resolution: bool = True):
        assert TAINT_EN
        assert self.instr_func_taint is not None, f"Cannot execute {self.get_str()}: no instr_func_taint found."
        assert self.fuzzerstate is not None, f"fuzzerstate not set, cannot execute {self.get_str()}" 
        rs1_val = self.fuzzerstate.intregpickstate.regs[self.rprod].get_val()
        rs1_val_taint = self.fuzzerstate.intregpickstate.regs[self.rprod].get_val_taint()
        if is_spike_resolution:
            rs2_val = self.fuzzerstate.intregpickstate.regs[RELOCATOR_REGISTER_ID].get_val()
            rs2_val_taint = self.fuzzerstate.intregpickstate.regs[RELOCATOR_REGISTER_ID].get_val_taint()
            assert rs2_val_taint == 0, f"reloc register {INTREG_ABINAMES[RELOCATOR_REGISTER_ID]} is tainted, this should not happen."
        else:
            rs2_val = self.fuzzerstate.intregpickstate.regs[self.rdep].get_val()
            rs2_val_taint = self.fuzzerstate.intregpickstate.regs[self.rdep].get_val_taint()
            assert rs2_val_taint == 0, f"rdep {INTREG_ABINAMES[self.rdep]} is tainted, this should not happen. {filter_reg_traceback(self.rdep, self.paddr,self.fuzzerstate,None, is_spike_resolution)}"

        assert rs1_val_taint == 0, f"rprod is tainted, this should not happen."
        # Compute the taint results of the operation.
        res_taint = self.instr_func_taint(rs1_val, rs1_val_taint, rs2_val, rs2_val_taint, self.fuzzerstate.is_design_64bit)
        # Compute alternative results if other soruce registers had been choosen.
        res_taint |= self.compute_alt_res_taint(res)

        assert res_taint == 0, f"Result of {self.get_str()} is tainted, this should not happen."
        # Writeback taints according to tainted bits in rd.
        self.writeback_taint(res_taint, res, is_spike_resolution)

    def execute(self, is_spike_resolution: bool = True):
        if not is_spike_resolution:
            self.assert_addr()
            self.fuzzerstate.curr_pc += (2 if self.iscompressed else 4)
        rprod_val = self.fuzzerstate.intregpickstate.regs[self.rprod].get_val()
        if is_spike_resolution:
            if USE_MMU and self.produce_va_layout != -1:
                self.fuzzerstate.advance_minstret()
                if TAINT_EN:
                    self.execute_taint(0x0, is_spike_resolution)
                    self.fuzzerstate.advance_minstret()
                return
            rdep_val = self.fuzzerstate.intregpickstate.regs[RELOCATOR_REGISTER_ID].get_val()
        else:
            rdep_val = self.fuzzerstate.intregpickstate.regs[self.rdep].get_val()  
        res = self.instr_func(rprod_val,rdep_val,self.fuzzerstate.is_design_64bit)
        if TAINT_EN:
            self.execute_taint(res, is_spike_resolution)
        self.fuzzerstate.intregpickstate.regs[self.rd].set_val(res)
        self.fuzzerstate.advance_minstret()


    def compute_alt_res_taint(self, res):
        assert TAINT_EN
        res_taint = 0x0
        for alt_rs1_id, alt_rs1 in self.fuzzerstate.intregpickstate.regs.items():
            if ((alt_rs1_id^self.rprod)&(~self.rprod_taint) == 0 and self.rprod_taint != 0) : # only differ in the tainted bits, therefore this register could have been used for addition instead and we need to derive the taints
                print(f"{INTREG_ABINAMES[alt_rs1_id]} matches {INTREG_ABINAMES[self.rprod]} in untainted bits")
                alt_res = self.instr_func(alt_rs1.get_val(), self.fuzzerstate.intregpickstate.regs[RELOCATOR_REGISTER_ID].get_val())
                res_taint |= alt_res^res
        return res_taint


class IntLoadInstruction_taint(IntLoadInstruction, RDInstruction_taint):
    def __init__(self, fuzzerstate, instr_str: str, rd: int, rs1: int, imm: int, producer_id: int, iscompressed: bool = False, is_rd_nonpickable_ok: bool = False):
        super().__init__(fuzzerstate, instr_str, rd, rs1, imm, producer_id, iscompressed, is_rd_nonpickable_ok)
        self.rd_taint = 0
        self.imm_taint = 0
        self.rs1_taint = 0
        self.n_bytes = 1 if "lb" in instr_str else 2 if "lh" in instr_str else 4 if "lw" in instr_str else 8 if "ld" in instr_str else -1
        assert self.n_bytes != -1 # sanity check
        self.mask = 2**(self.n_bytes*8)-1
        
    def execute(self, is_spike_resolution: bool = True):
        if not is_spike_resolution:
            self.assert_addr()
            self.fuzzerstate.curr_pc += (2 if self.iscompressed else 4)

        rs1_val = self.fuzzerstate.intregpickstate.regs[self.rs1].get_val()
        addr = INSTR_FUNCS["addi"](rs1_val,self.imm, self.fuzzerstate.is_design_64bit)

        try:
            res = self.fuzzerstate.memview.read(addr,self.n_bytes, self.priv_level, self.va_layout)
            if TAINT_EN:
                self.execute_taint(res, is_spike_resolution)
            res = self.instr_func(res,self.fuzzerstate.is_design_64bit)
            self.fuzzerstate.intregpickstate.regs[self.rd].set_val(res)
            self.fuzzerstate.advance_minstret()
        except AssertionError as e:
                if not self.isdead: # transient instructions fail silently
                    raise e

    def execute_taint(self, res, is_spike_resolution):
        assert TAINT_EN
        rs1_val = self.fuzzerstate.intregpickstate.regs[self.rs1].get_val()
        rs1_val_taint = self.fuzzerstate.intregpickstate.regs[self.rs1].get_val_taint()
        assert self.imm_taint == 0, f"Immediate is tainted ({hex(self.imm)}), this is not allowed."
        if rs1_val_taint:
            raise TaintedMemLoadException(
                                fuzzerstate=self.fuzzerstate,
                                reg_id=self.rs1,
                                instr=self
                                )
        addr = INSTR_FUNCS["addi"](rs1_val, self.imm, self.fuzzerstate.is_design_64bit)

        res_taint = self.fuzzerstate.memview.read_taint(addr,self.n_bytes, self.priv_level, self.va_layout)

        res_taint = self.instr_func_taint(res_taint,self.fuzzerstate.is_design_64bit)
        self.writeback_taint(res_taint,res, is_spike_resolution) # We allow the rd field to be tainted, thus taint could be propagated to several destination registers.


class IntStoreInstruction_taint(IntStoreInstruction, BaseInstruction_taint):
    def __init__(self, fuzzerstate, instr_str: str, rs1: int, rs2: int, imm: int, producer_id: int, iscompressed: bool = False):
        super().__init__(fuzzerstate, instr_str, rs1, rs2, imm, producer_id, iscompressed)
        self.imm_taint = 0
        self.rs1_taint = 0
        self.rs2_taint = 0
        self.n_bytes = 1 if "sb" in instr_str else 2 if "sh" in instr_str else 4 if "sw" in instr_str else 8 if "sd" in instr_str else -1
        assert self.n_bytes != -1
        self.mask = 2**(self.n_bytes*8)-1
    
    def execute(self, is_spike_resolution: bool = True):
        if not is_spike_resolution:
            self.assert_addr()
            self.fuzzerstate.curr_pc += (2 if self.iscompressed else 4)
        addr = INSTR_FUNCS["addi"](self.fuzzerstate.intregpickstate.regs[self.rs1].get_val(),self.imm, self.fuzzerstate.is_design_64bit)
        res = self.fuzzerstate.intregpickstate.regs[self.rs2].get_val()
        if TAINT_EN:
            self.execute_taint(res, is_spike_resolution)
        
        try:
            self.fuzzerstate.memview.write(addr, res&self.mask, 
            self.n_bytes, self.priv_level, self.va_layout)
            self.fuzzerstate.advance_minstret()
        except AssertionError as e:
            if not self.isdead:
                raise e


    def execute_taint(self, res, is_spike_resolution):
        assert TAINT_EN
        rs1_val = self.fuzzerstate.intregpickstate.regs[self.rs1].get_val()
        rs1_val_taint =  self.fuzzerstate.intregpickstate.regs[self.rs1].get_val_taint()
        assert self.imm_taint == 0, f"Immediate is tainted ({hex(self.imm)}), this is not allowed."
        if rs1_val_taint:
            raise TaintedMemStoreException(
                                fuzzerstate=self.fuzzerstate,
                                reg_id=self.rs1,
                                instr=self
                                )
            
        addr = INSTR_FUNCS["addi"](rs1_val,self.imm, self.fuzzerstate.is_design_64bit)
        rs2_val_taint =  self.fuzzerstate.intregpickstate.regs[self.rs2].get_val_taint()
        self.fuzzerstate.memview.write_taint(addr,rs2_val_taint&self.mask, self.n_bytes, self.priv_level, self.va_layout) # We don't allow addresses to be tainted, thus we don't need a writeback here.

    def get_str(self, is_spike_resolution: bool = USE_SPIKE_INTERM_ELF, color_taint: bool = PRINT_COLOR_TAINT):
        if not color_taint:
            return super().get_str()

        if self.fuzzerstate.intregpickstate.regs[self.rs1].get_val_taint():
            rs1_str = CRED + INTREG_ABINAMES[self.rs1] + CEND
        else:
            rs1_str = INTREG_ABINAMES[self.rs1]
        if self.fuzzerstate.intregpickstate.regs[self.rs2].get_val_taint():
            rs2_str = CRED + INTREG_ABINAMES[self.rs2] + CEND
        else:
            rs2_str = INTREG_ABINAMES[self.rs2]
        
        return f"{self.get_preamble()}: {self.instr_str} {rs2_str}, {self.imm}({rs1_str})"


class RegdumpInstruction_taint(IntStoreInstruction_taint):
    def gen_bytecode_int(self, is_spike_resolution: bool):
        if is_spike_resolution:
            return rv32i_addi(0x0,0x0,0x0) # Return nop for spike resolution
        else:
            return super().gen_bytecode_int(is_spike_resolution)

    def get_str(self, is_spike_resolution: bool = USE_SPIKE_INTERM_ELF, color_taint: bool = PRINT_COLOR_TAINT):
        assert self.fuzzerstate.intregpickstate.regs[self.rs1].get_val_taint() == 0, f"Regdump register is tainted, this should not happen."
        if not is_spike_resolution:
            if self.fuzzerstate.intregpickstate.regs[self.rs2].get_val_taint():
                return f"{self.get_preamble()}: {self.instr_str} " + CRED +  INTREG_ABINAMES[self.rs2] + CEND + f", {self.imm}({INTREG_ABINAMES[self.rs1]})"
            else:
                return f"{self.get_preamble()}: {self.instr_str} {INTREG_ABINAMES[self.rs2]}, {self.imm}({INTREG_ABINAMES[self.rs1]})"
        else:
            return f"{self.get_preamble()}: nop"

    def check_regs_taint(self,val_taint):
        assert TAINT_EN
        if PRINT_CHECK_REGS_TAINT:
            print(f"{hex(self.paddr)}: Checking register taint: {INTREG_ABINAMES[self.rs2]}: (sim) {hex( self.fuzzerstate.intregpickstate.regs[self.rs2].get_val_taint())} =?= (real) {hex(val_taint)}")
        mismatch = self.fuzzerstate.intregpickstate.regs[self.rs2].check_taint(val_taint)
        assert not mismatch, f"{hex(self.paddr)}: {self.instr_str}: (Regdump) Taint mismatch for {mismatch[0]}: {hex(mismatch[1])} != {hex(mismatch[2])}\n\t Traceback: {filter_reg_traceback(self.rs2,self.paddr,self.fuzzerstate,val_taint,False).get_str(False)}"
        if DUMP_WRITEBACK_TAINT:
            with open(self.fuzzerstate.env["WRITEBACK_PATH"], "a") as f:
                f.write(f"taint: {hex(self.paddr if not USE_MMU else self.vaddr)}, {self.rs2}, {hex( self.fuzzerstate.intregpickstate.regs[self.rs2].get_val_taint())}, {hex(val_taint)}\n")


    def check_regs(self,val):
        if PRINT_CHECK_REGS:
            print(f"{hex(self.paddr)}: Checking register value: {INTREG_ABINAMES[self.rs2]}:{hex(val)}")
        mismatch = self.fuzzerstate.intregpickstate.regs[self.rs2].check(val)
        assert not mismatch, f"{hex(self.paddr)}: {self.instr_str}: (Regdump) Value mismatch for {mismatch[0]}: {hex(mismatch[1])} != {hex(mismatch[2])}\n\t Traceback: {filter_reg_traceback(self.rs2,self.paddr,self.fuzzerstate,val,False).get_str(False)}"

        if DUMP_WRITEBACK:
            with open(self.fuzzerstate.env["WRITEBACK_PATH"], "a") as f:
                f.write(f"value: {hex(self.paddr if not USE_MMU else self.vaddr)}, {self.rs2}, {hex( self.fuzzerstate.intregpickstate.regs[self.rs2].get_val_taint())}, {hex(val)}\n")

    def execute(self, is_spike_resolution: bool = True):
        assert self.fuzzerstate.intregpickstate.regs[self.rs1].get_val_taint() == 0, f"Regdump register is tainted, this should not happen."
        if is_spike_resolution:
            self.fuzzerstate.advance_minstret()
        else:
            super().execute(is_spike_resolution)

class SpecialInstruction_taint(SpecialInstruction, BaseInstruction_taint):
    def __init__(self, fuzzerstate, instr_str: str, rd: int = 0, rs1: int = 0, iscompressed: bool = False):
        super().__init__(fuzzerstate, instr_str, rd, rs1, iscompressed)

    def execute(self, is_spike_resolution):
        if not is_spike_resolution:
            self.assert_addr()
            self.fuzzerstate.curr_pc += (2 if self.iscompressed else 4)
        self.fuzzerstate.advance_minstret()

    def execute_taint(self, res, is_spike_resolution):
        assert 0


class BranchInstruction_taint(BranchInstruction, ImmInstruction_taint):
    def __init__(self, fuzzerstate, instr_str: str, rs1: int, rs2: int, imm: int, imm_taint: int, plan_taken: bool, iscompressed: bool = False):
        super().__init__(fuzzerstate, instr_str, rs1, rs2, imm, plan_taken, iscompressed)
        self.imm_taint = imm_taint
        assert not (plan_taken and imm_taint)

    def execute(self, is_spike_resolution: bool = True):
        if not is_spike_resolution:
            self.assert_addr()
            self.fuzzerstate.curr_pc += self.imm if self.plan_taken else 4
        if TAINT_EN:
            self.execute_taint(None,is_spike_resolution)
        self.fuzzerstate.advance_minstret()
    
    def blacklist_transient_window(self):
        if self.plan_taken:
            next_trans_paddr = self.paddr+4 if not self.iscompressed else self.paddr+2
            if next_trans_paddr&PAGE_ALIGNMENT_MASK == self.paddr&PAGE_ALIGNMENT_MASK:
                self.fuzzerstate.blacklist_gadget_addr(next_trans_paddr,self.va_layout, self.priv_level)
        else:
            next_trans_paddr = self.paddr+self.imm
            if next_trans_paddr < self.fuzzerstate.memsize + SPIKE_STARTADDR and next_trans_paddr&PAGE_ALIGNMENT_MASK == self.paddr&PAGE_ALIGNMENT_MASK:
                self.fuzzerstate.blacklist_gadget_addr(next_trans_paddr,self.va_layout, self.priv_level)



    def execute_taint(self,res,is_spike_resolution):
        if self.fuzzerstate.intregpickstate.regs[self.rs1].get_val_taint():
            raise TaintedBranchException(
                                        fuzzerstate=self.fuzzerstate,
                                        reg_id=self.rs1,
                                        instr=self
                                        )

        if self.fuzzerstate.intregpickstate.regs[self.rs2].get_val_taint():
            raise TaintedBranchException(
                                        fuzzerstate=self.fuzzerstate,
                                        reg_id=self.rs2,
                                        instr=self
                                        )

    def gen_bytecode_int_taint(self, is_spike_resolution: bool):
        assert TAINT_EN
        rs2 = self.rs2
        rs1 = self.rs1
        imm = self.imm
        self.rd = 0x0 # set regs to taints to get taint bytecode
        self.rs1 = 0x0
        self.imm = self.imm_taint
        taint_bytecode = self.gen_bytecode_int(is_spike_resolution)
        self.rd = 0x00 # set regs to 0 to get taint bytecode mask to remove func and opcode fields
        self.rs1 = 0x00
        self.imm = 0x00
        taint_bytecode_mask = self.gen_bytecode_int(is_spike_resolution)
        self.rs1 = rs1
        self.rs2 = rs2
        self.imm = imm
        masked_taint = taint_bytecode ^ taint_bytecode_mask
        return masked_taint


    def get_str(self, is_spike_resolution: bool = USE_SPIKE_INTERM_ELF, color_taint: bool = PRINT_COLOR_TAINT):
        if not color_taint:
            return super().get_str()


        if self.fuzzerstate.intregpickstate.regs[self.rs1].get_val_taint():
            rs1_str = CRED + INTREG_ABINAMES[self.rs1] + CEND
        else:
            rs1_str = INTREG_ABINAMES[self.rs1]
        if self.fuzzerstate.intregpickstate.regs[self.rs2].get_val_taint():
            rs2_str = CRED + INTREG_ABINAMES[self.rs2] + CEND
        else:
            rs2_str = INTREG_ABINAMES[self.rs2]
        
        if self.imm_taint:
            imm_str = CRED + self.imm + CEND
        else:
            imm_str = self.imm


        return f"{self.get_preamble()}: {self.instr_str} {rs1_str}, {rs2_str}, {imm_str}"

class CSRRegInstruction_taint(CSRRegInstruction, RDInstruction_taint):
    def __init__(self, fuzzerstate, instr_str: str, rd: int, rs1: int, csr_id: int, iscompressed: bool = False, is_satp_smode = (False, None), mpp_val = None):
        super().__init__(fuzzerstate, instr_str, rd, rs1, csr_id, iscompressed, is_satp_smode, mpp_val)

    def execute(self, is_spike_resolution: bool = True):
        is_satp_smode, va_layout = self.is_satp_smode
        if not is_spike_resolution:
            self.assert_addr()
            self.fuzzerstate.curr_pc += (2 if self.iscompressed else 4)
            if USE_MMU and is_satp_smode:
                self.fuzzerstate.curr_pc = phys2virt(self.paddr+4, PrivilegeStateEnum.SUPERVISOR, va_layout,self.fuzzerstate,absolute_addr=False)
        rs1_val = self.fuzzerstate.intregpickstate.regs[self.rs1].get_val()
        csr_val = self.fuzzerstate.csrfile.regs[self.csr_id].get_val()
        res = self.instr_func(rs1_val, csr_val, self.fuzzerstate.is_design_64bit)
        if TAINT_EN:
            self.execute_taint(res,is_spike_resolution)
        self.fuzzerstate.csrfile.regs[self.csr_id].set_val(res)
        self.fuzzerstate.intregpickstate.regs[self.rd].set_val(csr_val)
        
        if USE_MMU and is_satp_smode:
            # The SATP write is followed by an SFENCE.VMA, which causes the page fault.
            self.fuzzerstate.csrfile.regs[CSR_IDS.SCAUSE].set_val(ExceptionCauseVal.ID_INSTRUCTION_PAGE_FAULT)
            self.fuzzerstate.csrfile.regs[CSR_IDS.SEPC].set_val(self.vaddr+4)

        if self.csr_id == CSR_IDS.MINSTRET and self.instr_str == "csrrw":
            return
        self.fuzzerstate.advance_minstret()

    def execute_taint(self,res,is_spike_resolution):
        rs1_val = self.fuzzerstate.intregpickstate.regs[self.rs1].get_val()
        rs1_val_taint = self.fuzzerstate.intregpickstate.regs[self.rs1].get_val_taint()
        csr_val = self.fuzzerstate.csrfile.regs[self.csr_id].get_val()
        csr_val_taint = self.fuzzerstate.csrfile.regs[self.csr_id].get_val_taint()
        res_taint = self.instr_func_taint(rs1_val, rs1_val_taint, csr_val, csr_val_taint, self.fuzzerstate.is_design_64bit)
        self.fuzzerstate.csrfile.regs[self.csr_id].set_val_taint(res_taint)
        self.writeback_taint(csr_val_taint,csr_val,is_spike_resolution)

class CSRImmInstruction_taint(CSRImmInstruction, RDInstruction_taint):
    def __init__(self, fuzzerstate, instr_str: str, rd: int, uimm: int, csr_id: int, iscompressed: bool = False):
        super().__init__(fuzzerstate, instr_str, rd, uimm, csr_id, iscompressed)
        self.uimm_taint = 0

    def execute(self, is_spike_resolution: bool = True):
        if not is_spike_resolution:
            self.assert_addr()
            self.fuzzerstate.curr_pc += (2 if self.iscompressed else 4)
        csr_val = self.fuzzerstate.csrfile.regs[self.csr_id].get_val()
        res = self.instr_func(self.uimm, csr_val, self.fuzzerstate.is_design_64bit)
        if TAINT_EN:
            self.execute_taint(res,is_spike_resolution)
        self.fuzzerstate.csrfile.regs[self.csr_id].set_val(res)
        self.fuzzerstate.intregpickstate.regs[self.rd].set_val(csr_val)
        if self.csr_id == CSR_IDS.MINSTRET and self.instr_str == "csrrwi":
            return
        self.fuzzerstate.advance_minstret()

    def execute_taint(self,res,is_spike_resolution):
        csr_val = self.fuzzerstate.csrfile.regs[self.csr_id].get_val()
        csr_val_taint = self.fuzzerstate.csrfile.regs[self.csr_id].get_val_taint()
        res_taint = self.instr_func_taint(self.uimm, self.uimm_taint, csr_val, csr_val_taint, self.fuzzerstate.is_design_64bit)
        self.fuzzerstate.csrfile.regs[self.csr_id].set_val_taint(res_taint)
        self.writeback_taint(csr_val_taint,csr_val,is_spike_resolution)

# Used to check if a register dump should be inserted after instruction in Fuzzerstate::appen_and_execute if enabled.
def has_taint_trace(obj):
    return isinstance(obj, (RegImmInstruction_taint, ImmRdInstruction_taint, R12DInstruction_taint, CSRImmInstruction_taint, CSRRegInstruction_taint, IntLoadInstruction_taint))

class MstatusWriterInstruction_taint(MstatusWriterInstruction, BaseInstruction_taint):
    def __init__(self, rd: int, rs1: int, producer_id: int, instr_str: str, mstatus_mask: int, old_sum_mprv=...):
        super().__init__(rd, rs1, producer_id, instr_str, mstatus_mask, old_sum_mprv)
        self.csr_instr = CSRRegInstruction_taint(instr_str, rd, rs1, CSR_IDS.MSTATUS)

    def execute(self, is_spike_resolution: bool = True):
        self.csr_instr.execute(is_spike_resolution)
        
class TvecWriterInstruction_taint(TvecWriterInstruction, BaseInstruction_taint):
    def __init__(self, fuzzerstate, is_mtvec: bool, rd: int, rs1: int, producer_id: int):
        super().__init__(fuzzerstate, is_mtvec, rd, rs1, producer_id)
        csr_id = CSR_IDS.MTVEC if is_mtvec else CSR_IDS.STVEC
        self.csr_instr = CSRRegInstruction_taint(fuzzerstate, "csrrw", rd, rs1, csr_id)
        assert self.paddr == self.csr_instr.paddr

    def execute(self, is_spike_resolution: bool = True):
        self.csr_instr.execute(is_spike_resolution)
    
class EPCWriterInstruction_taint(EPCWriterInstruction, BaseInstruction_taint):  
    def __init__(self, fuzzerstate, is_mepc: bool, rd: int, rs1: int, producer_id: int):
        super().__init__(fuzzerstate, is_mepc, rd, rs1, producer_id)
        self.rd = rd
        self.rs1 = rs1
        self.csr_id = CSR_IDS.MEPC if is_mepc else CSR_IDS.SEPC
        self.csr_instr = CSRRegInstruction_taint(fuzzerstate, "csrrw", rd, rs1, self.csr_id)
        assert self.paddr == self.csr_instr.paddr

    def execute(self, is_spike_resolution: bool = True):
        self.csr_instr.execute(is_spike_resolution)

class GenericCSRWriterInstruction_taint(GenericCSRWriterInstruction, BaseInstruction_taint):
    def __init__(self, fuzzerstate, csr_id: int, rd: int, rs1: int, producer_id: int, val_to_write_spike: int, val_to_write_cpu: int):
        super().__init__(fuzzerstate, csr_id, rd, rs1, producer_id, val_to_write_spike, val_to_write_cpu)
        self.rd = rd
        self.rs1 = rs1
        self.csr_instr = CSRRegInstruction_taint(fuzzerstate,"csrrw", rd, rs1, csr_id)
        assert self.paddr == self.csr_instr.paddr

    def execute(self, is_spike_resolution: bool = True):
        self.csr_instr.execute(is_spike_resolution)


class PrivilegeDescentInstruction_taint(PrivilegeDescentInstruction, BaseInstruction_taint):
    def execute(self, is_spike_resolution: bool = USE_SPIKE_INTERM_ELF):
        if self.is_mret:
            self.execute_mret()
        else:
            self.execute_sret()

    def blacklist_transient_window(self):
        next_trans_paddr = self.paddr+4 if not self.iscompressed else self.paddr+2
        if next_trans_paddr&PAGE_ALIGNMENT_MASK == self.paddr&PAGE_ALIGNMENT_MASK:
            self.fuzzerstate.blacklist_gadget_addr(next_trans_paddr,self.va_layout, self.priv_level)


    def execute_mret(self):
        self.fuzzerstate.curr_pc = self.fuzzerstate.csrfile.regs[CSR_IDS.MEPC].get_val()
        self.fuzzerstate.advance_minstret()

    def execute_sret(self):
        self.fuzzerstate.curr_pc = self.fuzzerstate.csrfile.regs[CSR_IDS.SEPC].get_val()
        self.fuzzerstate.advance_minstret()



class SimpleIllegalInstruction_taint(SimpleIllegalInstruction, BaseInstruction_taint):
    def execute(self, is_spike_resolution: bool = USE_SPIKE_INTERM_ELF):
        if not is_spike_resolution:
            self.assert_addr()
        if self.is_mtvec:
            self.fuzzerstate.csrfile.regs[CSR_IDS.MEPC].set_val(self.vaddr if USE_MMU else self.paddr)
            self.fuzzerstate.csrfile.regs[CSR_IDS.MCAUSE].set_val(ExceptionCauseVal.ID_ILLEGAL_INSTRUCTION)
        else:
            self.fuzzerstate.csrfile.regs[CSR_IDS.SEPC].set_val(self.vaddr if USE_MMU else self.paddr)
            self.fuzzerstate.csrfile.regs[CSR_IDS.SCAUSE].set_val(ExceptionCauseVal.ID_ILLEGAL_INSTRUCTION)

        self.fuzzerstate.curr_pc = self.fuzzerstate.csrfile.regs[CSR_IDS.MTVEC].get_val() if self.is_mtvec else self.fuzzerstate.csrfile.regs[CSR_IDS.STVEC].get_val()

    def blacklist_transient_window(self):
        next_trans_paddr = self.paddr+4 if not self.iscompressed else self.paddr+2
        if next_trans_paddr&PAGE_ALIGNMENT_MASK == self.paddr&PAGE_ALIGNMENT_MASK:
            self.fuzzerstate.blacklist_gadget_addr(next_trans_paddr,self.va_layout, self.priv_level)



class SimpleExceptionEncapsulator_taint(SimpleExceptionEncapsulator, BaseInstruction_taint):
    def execute(self, is_spike_resolution: bool = True):
        if not is_spike_resolution:
            self.assert_addr()
        if self.is_mtvec:
            self.fuzzerstate.csrfile.regs[CSR_IDS.MEPC].set_val(self.vaddr if USE_MMU else self.paddr)
            self.fuzzerstate.csrfile.regs[CSR_IDS.MCAUSE].set_val(self.exception_op_type)
        else:
            self.fuzzerstate.csrfile.regs[CSR_IDS.SEPC].set_val(self.vaddr if USE_MMU else self.paddr)
            self.fuzzerstate.csrfile.regs[CSR_IDS.SCAUSE].set_val(self.exception_op_type)
        self.fuzzerstate.curr_pc = self.fuzzerstate.csrfile.regs[CSR_IDS.MTVEC].get_val() if self.is_mtvec else self.fuzzerstate.csrfile.regs[CSR_IDS.STVEC].get_val()

    def blacklist_transient_window(self):
        next_trans_paddr = self.paddr+4 if not self.iscompressed else self.paddr+2
        if next_trans_paddr&PAGE_ALIGNMENT_MASK == self.paddr&PAGE_ALIGNMENT_MASK:
            self.fuzzerstate.blacklist_gadget_addr(next_trans_paddr,self.va_layout, self.priv_level)

class MisalignedMemInstruction_taint(MisalignedMemInstruction, BaseInstruction_taint):
    def execute(self, is_spike_resolution: bool = True):
        if not is_spike_resolution:
            self.assert_addr()
        if self.is_mtvec:
            self.fuzzerstate.csrfile.regs[CSR_IDS.MEPC].set_val(self.vaddr if USE_MMU else self.paddr)
            self.fuzzerstate.csrfile.regs[CSR_IDS.MCAUSE].set_val(self.exceptioncause_val)
        else:
            self.fuzzerstate.csrfile.regs[CSR_IDS.SEPC].set_val(self.vaddr if USE_MMU else self.paddr)
            self.fuzzerstate.csrfile.regs[CSR_IDS.SCAUSE].set_val(self.exceptioncause_val)
        self.fuzzerstate.curr_pc = self.fuzzerstate.csrfile.regs[CSR_IDS.MTVEC].get_val() if self.is_mtvec else self.fuzzerstate.csrfile.regs[CSR_IDS.STVEC].get_val()

    def blacklist_transient_window(self):
        next_trans_paddr = self.paddr+4 if not self.iscompressed else self.paddr+2
        if next_trans_paddr&PAGE_ALIGNMENT_MASK == self.paddr&PAGE_ALIGNMENT_MASK:
            self.fuzzerstate.blacklist_gadget_addr(next_trans_paddr,self.va_layout, self.priv_level)

class RawDataWord_taint(RawDataWord):
    def __init__(self, fuzzerstate, wordval: int, wordval_taint: int = 0, signed: bool = False):
        super().__init__(fuzzerstate, wordval, signed)
        if DO_ASSERT:
            if signed:
                assert wordval_taint >= -(1 << 31)
                assert wordval_taint < (1 << 32), f"signed wordval: {wordval}, 1 << 32: {1 << 32}"
            else:
                assert wordval_taint >= 0
                assert wordval_taint < (1 << 32), f"unsigned wordval: {hex(wordval)}, 1 << 32: {hex(1 << 32)}"
        self.wordval_taint = wordval_taint
        if signed:
            if wordval_taint < 0:
                self.wordval_taint = wordval_taint + (1 << 32)

    def gen_bytecode_int_taint(self, is_spike_resolution: bool):
        return self.wordval_taint
    
    def get_str(self, is_spike_resolution: bool = True, color_taint: bool = PRINT_COLOR_TAINT):
        return f"{hex(self.paddr)}: {hex(self.wordval)}, {hex(self.wordval_taint)} (RAW DATA)"
    
    def execute(self, is_spike_resolution: bool = True):
        return

    def write(self, is_spike_resolution: bool = False):
        if DO_ASSERT:
            assert self.paddr >= SPIKE_STARTADDR
            assert self.paddr < SPIKE_STARTADDR + self.fuzzerstate.memsize
        super().write(is_spike_resolution)
        self.write_taint(is_spike_resolution)

    def write_taint(self, is_spike_resolution: bool = False):
        if DO_ASSERT:
            assert self.paddr >= SPIKE_STARTADDR
            assert self.paddr < SPIKE_STARTADDR + self.fuzzerstate.memsize
        self.fuzzerstate.memview.write_taint(self.paddr, self.gen_bytecode_int_taint(is_spike_resolution), 4)

