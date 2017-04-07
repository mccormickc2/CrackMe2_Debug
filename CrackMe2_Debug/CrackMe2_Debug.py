#---------------------------------------------------------------------
# Debug notification hook test
#
# This script start the executable and steps through the first five
# instructions. Each instruction is disassembled after execution.
#
# Author: Gergely Erdelyi <dyce@d-dome.net>
#---------------------------------------------------------------------
from idaapi import *

class MyDbgHook(DBG_Hooks):
    """ Own debug hook class that implementd the callback functions """

    def dbg_process_start(self, pid, tid, ea, name, base, size):
        print "Process started, pid=%d tid=%d name=%s" % (pid, tid, name)
        return 0

    def dbg_process_exit(self, pid, tid, ea, code):
        print "Process exited pid=%d tid=%d ea=0x%x code=%d" % (pid, tid, ea, code)
        return 0

    def dbg_library_load(self, pid, tid, ea, name, base, size):
        print "Library loaded: pid=%d tid=%d name=%s base=%x" % (pid, tid, name, base)

    # Added code starts here.
    def dbg_bpt(self, tid, ea):
        print "Break point at 0x%x pid=%d" % (ea, tid)
        # Gets the value of the 'cl' register right before the final test is called
        # If the password is the original correct password, the register 'cl' should contain 0 and thus we change this to any non-zero number to make it incorrect.
        # Similarly, if the password was originally incorrect, the register 'cl' should contain a non-zero number and thus we change this to 0 to make it correct.
        if(ea == 0x0040123C):
            compare = GetRegValue("cl")
            if(compare == 0):
                rv = idaapi.regval_t()
                rv.ival = 1
                idaapi.set_reg_val("cl", rv)
            else:
                rv = idaapi.regval_t()
                rv.ival = 0
                idaapi.set_reg_val("cl", rv)   
        # Print entered password (currently in hex).
        if(ea == 0x00401370): 
            esi = GetRegValue("esi")
            print("Password was %X\n" % (Dword(esi)))
        return 0
    # End added code.

    def dbg_trace(self, tid, ea):
        print tid, ea
        return 0

    def dbg_step_into(self):
        print "Step into"
        return self.dbg_step_over()

    def dbg_step_over(self):
        eip = GetRegValue("EIP")
        print "0x%x %s" % (eip, GetDisasm(eip))

        self.steps += 1
        if self.steps >= 5:
            request_exit_process()
        else:
            request_step_over()
        return 0

# Remove an existing debug hook
try:
    if debughook:
        print "Removing previous hook ..."
        debughook.unhook()
except:
    pass

# Install the debug hook
debughook = MyDbgHook()
debughook.hook()
debughook.steps = 0

# Stop at the entry point
ep = GetLongPrm(INF_START_IP)
request_run_to(ep)

# Step one instruction
request_step_over()

# Start debugging
run_requests()

# Add breakpoint right before final test is called.
AddBpt(0x0040123C)
AddBpt(0x00401370)

